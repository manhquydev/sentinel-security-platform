(() => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const capability = fragment.get("startup_capability");
  history.replaceState(null, "", location.pathname);

  function addCard(title, lines) {
    const card = document.createElement("article");
    card.className = "card";
    const heading = document.createElement("h2");
    heading.textContent = title;
    card.appendChild(heading);
    for (const [label, value] of lines) {
      const paragraph = document.createElement("p");
      if (label) {
        const labelNode = document.createElement("span");
        labelNode.className = "label";
        labelNode.textContent = `${label}: `;
        paragraph.appendChild(labelNode);
      }
      paragraph.append(value);
      card.appendChild(paragraph);
    }
    document.querySelector("#cards").appendChild(card);
  }

  function renderCards(view) {
    const research = view.research;
    const cmc = view.cmc;
    document.querySelector("#cards").replaceChildren();
    addCard("Research result", [
      ["State", research.state],
      ["Why", research.reason_code],
      ["Meaning", research.operator_summary],
    ]);
    addCard("Deterministic controls", Object.entries(research.controls).map(([name, control]) => [
      `${name} — ${control.state}`, control.detail,
    ]));
    addCard("AI experiment boundary", [
      ["State", research.controls.B3.state],
      ["Egress", research.b3_egress_notice],
      ["Rule", "AI proposals cannot suppress or downgrade deterministic scanner findings."],
    ]);
    addCard("CMC EDU boundary", [
      ["Classification", cmc.classification],
      ["Value gate", `${cmc.status}: ${cmc.reason}`],
      ["Meaning", cmc.detail],
    ]);
    addCard("Local containment", [
      ["UI", "Loopback-only, unprivileged Compose service."],
      ["Host", "Only host-owned workers can read sealed bytes, invoke scanners, or hold the B3 credential."],
      ["Evidence", "Sanitized browser output never contains source text, secrets, or provider responses."],
    ]);
  }

  function addFixtureTransportAction(view, csrfToken) {
    if (!csrfToken || !view.fixture_transport || !view.broker) {
      return;
    }
    const card = document.createElement("article");
    card.className = "card";
    const heading = document.createElement("h2");
    heading.textContent = "Fixture transport check";
    const description = document.createElement("p");
    description.textContent = view.fixture_transport.detail;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Run safe readiness check";
    const outcome = document.createElement("p");
    card.append(heading, description, button, outcome);
    document.querySelector("#cards").appendChild(card);

    button.addEventListener("click", async () => {
      button.disabled = true;
      outcome.textContent = "Submitting the metadata-only readiness command…";
      try {
        const submitted = await fetch(`${view.broker.origin}/api/commands`, {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-Workbench-CSRF": csrfToken,
          },
          body: JSON.stringify(view.fixture_transport.command),
        });
        if (!submitted.ok) {
          throw new Error("broker-refused-command");
        }
        const command = await submitted.json();
        for (let attempt = 0; attempt < 40; attempt += 1) {
          const statusResponse = await fetch(`${view.broker.origin}/api/status`, {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
              "Content-Type": "application/json",
              "X-Workbench-CSRF": csrfToken,
            },
            body: JSON.stringify({ command_id: command.command_id }),
          });
          if (!statusResponse.ok) {
            throw new Error("broker-refused-status");
          }
          const status = await statusResponse.json();
          if (status.status === "succeeded") {
            outcome.textContent = "Fixture transport completed without exposing source.";
            return;
          }
          if (status.status === "failed") {
            outcome.textContent = "Readiness check refused before any source scan because scanner policy is not ready.";
            return;
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        outcome.textContent = "Readiness command did not reach a terminal state; no scan result is claimed.";
      } catch (_error) {
        outcome.textContent = "Readiness command was refused; no scan result is claimed.";
      } finally {
        button.disabled = false;
      }
    });
  }

  async function render() {
    const response = await fetch("/api/view", { credentials: "same-origin", cache: "no-store" });
    const view = await response.json();
    let status = "Read-only evidence state.";
    let csrfToken = null;
    if (capability && view.broker && view.broker.origin) {
      const bootstrap = await fetch(`${view.broker.origin}/api/bootstrap`, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ startup_capability: capability }),
      });
      if (bootstrap.ok) {
        csrfToken = (await bootstrap.json()).csrf_token;
        status = "Broker session established; source and worker access remain host-owned.";
      } else {
        status = "Broker bootstrap was refused; the UI remains read-only.";
      }
    } else if (capability) {
      status = "Bootstrap capability cleared; no configured broker is available for actions.";
    }
    document.querySelector("#status").textContent = status;
    renderCards(view);
    addFixtureTransportAction(view, csrfToken);
  }

  render().catch(() => {
    document.querySelector("#status").textContent = "Unable to load the metadata-only evidence state.";
  });
})();
