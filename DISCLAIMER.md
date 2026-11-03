# Disclaimer and Limitation of Liability

## No warranty

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and non-infringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in the
software. (MIT license terms apply in full; see LICENSE.)

## Audit tooling, not an audit

Running these checks does not constitute a security audit, a penetration
test, or a professional assurance engagement. A clean report is not a
guarantee that an environment is secure. Findings are point-in-time
observations and may be incomplete, outdated, or wrong.

## Read-only by design, not by guarantee

The tooling is designed to be read-only. You remain responsible for how you
run it, against which environments, and with which credentials. Review every
command before running it in an environment you care about. The authors are
not liable for any damage, outage, data loss, or cost resulting from running
this tooling or from acting or failing to act on its output.

## Agent use

This tooling is intended to be executed by AI agents. AI agents can make
mistakes, misread instructions, or execute commands in the wrong context.
Never give an agent credentials broader than the audit needs, never run it
against production without a human reviewing the plan, and treat all output
as unverified until a human confirms it.

## Not legal or compliance advice

Nothing in this repository is legal, regulatory, or compliance advice.
Passing these checks does not imply compliance with SOC 2, ISO 27001, GDPR,
HIPAA, or any other framework.
