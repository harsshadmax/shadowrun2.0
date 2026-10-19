# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
def export_report(rows):
    return "\n".join(",".join(map(str, r)) for r in rows)
