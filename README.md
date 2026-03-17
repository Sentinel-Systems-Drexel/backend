## Persistent Email Analysis Storage

Email analysis files are stored in a host-mounted directory so they persist across container restarts and rebuilds.

- Host path: `./email-analysis-data`
- Container path: `/data/email-analysis`

The API writes outputs to the directory set by `EMAIL_ANALYSIS_DIR` (default: `/data/email-analysis`).