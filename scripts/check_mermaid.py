"""Extract the Mermaid blocks of README.md into an HTML page (served locally) so they can be parse-checked in a browser."""
import html
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
blocks = re.findall(r"```mermaid\n(.*?)```", (root / "README.md").read_text(), re.S)
out = root / ".data" / "mermaid_check"
out.mkdir(parents=True, exist_ok=True)
divs = "\n".join(f'<h4>Diagram {i}</h4><pre class="mermaid" id="d{i}">{html.escape(b)}</pre>' for i, b in enumerate(blocks, 1))
(out / "index.html").write_text(f"""<!doctype html><meta charset="utf-8"><body style="background:#fff">
{divs}
<script type="module">
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.esm.min.mjs";
mermaid.initialize({{ startOnLoad: false }});
window.mermaid = mermaid;
const results = [];
for (const el of document.querySelectorAll("pre.mermaid")) {{
  try {{ await mermaid.parse(el.textContent); results.push(el.id + ": ok"); }}
  catch (e) {{ results.push(el.id + ": ERROR " + String(e.message || e).split("\\n")[0]); }}
}}
await mermaid.run({{ querySelector: "pre.mermaid" }});
window.__results = results;
</script>""")
print(f"{len(blocks)} diagrams written to {out}")
sys.exit(0)
