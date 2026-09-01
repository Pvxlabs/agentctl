# ORION Adapter Contract

This directory contains a contract only. It does not copy ORION source and it
does not call an ORION endpoint.

The target API should expose these exact actions through the existing canonical
release path:

| Action | Method | Scope |
| --- | --- | --- |
| `strategy.release.read` | `GET` | `strategy.release.read` |
| `strategy.release.import` | `POST` | `strategy.release.import` |
| `strategy.release.approve` | `POST` | `strategy.release.approve` |
| `strategy.release.activate` | `POST` | `strategy.release.activate` |

The receiving ORION middleware verifies the machine assertion, then passes the
request to the existing `StrategyReleaseRepository` and ORION domain
authority. Approval, activation, transaction validity, and canonical readback
remain ORION decisions.
