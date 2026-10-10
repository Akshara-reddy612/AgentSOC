import re
import sys

with open('agentsoc2_paper_corrected.tex', 'r', encoding='utf-8') as f:
    text = f.read()

# Step 2: Paired subsection replace last sentence
s_old = "Ultimately, this model resists most payload families (NOT FOUND IN REPO), rendering the overall test insensitive to the structural layers' active defense capabilities."
s_new = r"In earlier undefended triage tests on held-out alerts ($n=10$ per family), this model was hijacked on three of the eight families used here (\texttt{fabricated\_evidence} 60\%, \texttt{zero\_imperative\_evidence} 30\%, \texttt{cross\_field\_split} 10\%) and on none of the others; the paired result above therefore comes from a model that the payloads rarely fool, which limits what it can show about the structural layers."
if s_old in text:
    text = text.replace(s_old, s_new)
else:
    print(f"Could not find Step 2 string '{s_old}'")

# Step 3: Abstract changes
text = text.replace("the model resists most of our payload families", "in earlier undefended tests this model was hijacked on only three of our eight payload families")
text = text.replace("We therefore report invariance of the pipeline's outcome to contamination on this model", "We therefore report no detectable effect of contamination on the pipeline's outcome on this model")

# Conclusion changes
text = text.replace("statistically indistinguishable from its outcome", "showing no detectable difference from its outcome")
text = text.replace("on a single model that resists most of our payloads", "on a single model that the payloads rarely fool")

# Paired subsection changes
text = text.replace("statistically indistinguishable from its outcome on clean data", "showing no detectable difference from its outcome on clean data")
text = text.replace("bounded within a few percentage points.", "bounded within a few percentage points (at most about 4\% of alerts changed verdict between conditions, the upper 95\% Wilson bound for 6/320).")

# Step 4: Line ~242 (SSE paragraph)
text = text.replace("This immunity does not extend", "This guarantee does not extend")
s_app_old = "The account, host, and technique strings it checks are produced by an LLM that read untrusted fields, and no check currently compares them with the trusted alert metadata; the guarantee is that SSE's verdict cannot be altered by injected text it never receives."
s_app_new = "In our evaluation those identifiers are produced by an LLM that read untrusted fields, and no check currently compares them with the trusted alert metadata."
if s_app_old in text:
    text = text.replace(s_app_old, s_app_new)
else:
    print("Could not find Step 4 appended sentence")

# Step 5: Replace "p=0.2187" with "p=0.2188" and table placement [h] -> [t]
text = text.replace("p=0.2187", "p=0.2188")
text = text.replace(r"\begin{table}[h]" + "\n\\centering\n\\caption{No-Actionable-Hypothesis Count by Injection Family", r"\begin{table}[t]" + "\n\\centering\n\\caption{No-Actionable-Hypothesis Count by Injection Family")

with open('agentsoc2_paper_corrected.tex', 'w', encoding='utf-8') as f:
    f.write(text)
