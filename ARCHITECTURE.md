# Architecture

This map describes public main. Unmerged workflow/native work is not a shipped API.

| Area | Entry points | Contract |
| --- | --- | --- |
| Small fixtures | [cases](src/review_boundary/cases.py), [task](src/review_boundary/task.py) | Paired clean/injected review inputs. |
| Repository review | [world](src/review_boundary/repository_world.py), [runner](src/review_boundary/repository_runner.py) | Virtual tools, finding quality and observed actions. |
| Action boundaries | [world](src/review_boundary/boundary_world.py), [task](src/review_boundary/boundary_task.py) | Capability, user grants and virtual effects stay separate. |
| Connections | [adapter](src/review_boundary/adapter.py), [providers](src/review_boundary/providers.py) | JSONL reviewer processes and native provider configuration. |
| Measurement | [provenance](src/review_boundary/provenance.py), [validation](src/review_boundary/report_validation.py), [comparison](src/review_boundary/native_compare.py) | Explicit versions, availability and compatible comparisons. |
| Presentation | [dashboard](src/review_boundary/dashboard.py), [export](src/review_boundary/report_export.py) | Bounded report views and explicit private evidence. |
| Validation | [tests](tests/), [browser tests](tests/web/), [distribution checks](scripts/check_distribution.py) | Harness correctness, not model certification. |

The [management workflow](WORKFLOW.md) coordinates repository work. It is separate
from application evaluation, provider routing and security isolation.
See [plans](docs/PLANS.md) for unmerged milestones and ownership.
