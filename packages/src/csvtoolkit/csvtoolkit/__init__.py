# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import csv
import io


def to_csv(rows):
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return buf.getvalue()
