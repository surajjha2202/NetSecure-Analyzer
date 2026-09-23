\# NetSecure Analyzer



\## AI-Driven Multi-Vendor Network Security Compliance Auditor



NetSecure Analyzer is a web-based network security configuration auditing platform for heterogeneous network environments. It ingests network-device configurations, detects vendors and device characteristics, normalizes security settings into a common baseline, evaluates compliance against multiple security frameworks, identifies unknown syntax through an AI-assisted learning workflow, and produces actionable remediation and reporting.



\## Core Capabilities



\- Single configuration ingestion

\- Bulk configuration ingestion

\- Multi-vendor detection and parsing

\- Device intelligence

\- Vendor/product/model/firmware/serial-number extraction

\- Security baseline normalization

\- Multi-framework compliance analysis

&#x20; - CIS

&#x20; - NIST

&#x20; - DISA STIG

&#x20; - ISO/IEC 27001

\- PASS / FAIL / N/A control evaluation

\- Risk calculation

\- Unknown configuration syntax detection

\- AI-assisted human learning workflow

\- Administrator-approved learned mappings

\- Device-specific remediation recommendations

\- Remediation approval and verification

\- Role-based access control

\- User-scoped configurations and devices

\- Audit trail

\- Security assessment reporting

\- Browser Print / Save PDF workflow

\- Live SSH scanning for supported network devices



\## Architecture



```text

&#x20;                   React + Vite

&#x20;                        |

&#x20;                        v

&#x20;                  Web Dashboard

&#x20;                        |

&#x20;                        v

&#x20;                   FastAPI API

&#x20;                        |

&#x20;       +----------------+----------------+

&#x20;       |                |                |

&#x20;       v                v                v

&#x20;Configuration     Device Intelligence   Authentication

&#x20;  Ingestion       \& Vendor Detection    \& RBAC

&#x20;       |                |

&#x20;       +--------+-------+

&#x20;                |

&#x20;                v

&#x20;        Configuration Parser

&#x20;                |

&#x20;                v

&#x20;       Security Baseline Model

&#x20;                |

&#x20;                v

&#x20;       Multi-Framework Engine

&#x20;         /       |        \\

&#x20;       CIS      NIST    DISA STIG

&#x20;                |

&#x20;             ISO 27001

&#x20;                |

&#x20;                v

&#x20;            Risk Engine

&#x20;                |

&#x20;                v

&#x20;      Remediation \& Verification

&#x20;                |

&#x20;         +------+------+

&#x20;         |             |

&#x20;         v             v

&#x20;      Audit         Reporting



&#x20;PostgreSQL -> persistent application data

&#x20;Redis      -> runtime/cache services

&#x20;Alembic    -> database migrations
