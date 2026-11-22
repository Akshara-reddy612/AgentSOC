"""Cut Fig. 1's tikzpicture out of paper/agentsoc_v2.tex and wrap it in the paper's own class (IEEEtran,
same fonts and hyphenation), cropped to the picture with the preview package."""
from pathlib import Path

t = Path(r"D:\agentsoc\paper\agentsoc_v2.tex").read_text(encoding="utf-8")
lines = t.splitlines()
s = next(i for i, l in enumerate(lines) if l.startswith(r"\begin{tikzpicture}[font=\footnotesize"))
e = next(i for i in range(s, len(lines)) if lines[i].startswith(r"\end{tikzpicture}"))
head = r"""\documentclass[conference]{IEEEtran}
\usepackage[paperwidth=230mm,paperheight=120mm,margin=5mm]{geometry}
\usepackage{xcolor}\usepackage{tikz}\usetikzlibrary{arrows.meta,patterns}
\definecolor{ctrust}{HTML}{199E70}\definecolor{cllm}{HTML}{3987E5}\definecolor{ctext}{HTML}{D95926}\definecolor{csafe}{HTML}{7B4FB3}
\begin{document}
\pagestyle{empty}
\onecolumn
\noindent
"""
Path(__file__).with_name("fig1_ieee.tex").write_text(head + "\n".join(lines[s:e + 1]) + "\n\\end{document}\n",
                                                     encoding="utf-8")
print("ok")
