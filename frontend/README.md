# AgentSOC demo frontend

React + TypeScript (Vite) app for the demo in `PROJECT_PLAN.md` section 5: a day in the SOC during the DEDALE attack.

## Run the demo

1. **Build the app (once, and after frontend changes):**
   ```
   cd frontend
   npm install        # exact versions in package.json / package-lock.json
   npm run build      # typecheck + production build into frontend/dist
   ```
2. **Start the server:** `python -m soc_server`
   - The first start learns the two benign weeks and fast-forwards to the attack morning (a few minutes).
   - Open http://127.0.0.1:8000/.
3. **First run:** with no accounts yet, the page asks you to create the admin account. Then add the analysts' and leads' accounts on the Accounts page. (The command line can also create accounts: `python -m review_api.accounts --db <home>/auth.sqlite create-user <name> --role admin`; the default `<home>` is `D:\agentsoc_data\live`.)
4. **Start the replay:** a lead or admin presses Start on the Live page.

## Develop

Run `npm run dev` (http://127.0.0.1:5173) with `python -m soc_server` running. The dev server proxies `/api` to it; set `AGENTSOC_API` for another address.

## Pages

| Page | Shows |
|:--|:--|
| Live | Replay clock and controls (or "live logs" when the server follows log files), status tiles, the prioritised review queue |
| Case | The pipeline trace, verdicts with a learning preview, containment approval / rollback (four-eyes on critical hosts), withdrawing a wrong malicious verdict (lead / admin), related cases, notes, audit |
| Knowledge Store | What has been learned and from where (graph per host), retractions |
| Metrics | Frozen learning-mode comparison, the session's cases and learning per day |
| My account | Your role; change your password (your other sessions are signed out) |
| Accounts | Admin only: create accounts, change roles, disable / enable, reset passwords |

The Case page's pipeline trace covers, in order: the alert (trusted fields and untrusted text kept apart), the triage gate, the LLM hypotheses (labelled as LLM output), structural feasibility and entity binding, response ranking and guardrails, the decision, containment, and what the store learns.

Untrusted text from logs is always rendered as text, never as HTML.

**Possible steering:** when entity binding finds that an LLM hypothesis names an account or host the alert's trusted fields do not support ("unbound"), the case view marks where that name appears in the untrusted text and lists it in the structural-check table. The marks inform the analyst; they change no decision. Run the server with `--inject steer` to see them on the attacker's own commands.

## Check it like a user

`python tools/ui_check.py OUT "/,/cases/case-20,/knowledge,/metrics" pw.txt <user> http://127.0.0.1:8000`

This drives headless Edge, saves screenshots and prints JavaScript errors. In Git Bash, set `MSYS_NO_PATHCONV=1` first.
