---
title: "AI laws and acts around the globe: what every AI platform builder needs to know"
description: "platform engineers, architects, and compliance teams building or deploying AI systems that operate across jurisdictions"
pubDate: "2026-06-20"
---

*Audience: platform engineers, architects, and compliance teams building or deploying AI systems that operate across jurisdictions*

---

I've been building software long enough to remember when GDPR was just a draft. At the time, a lot of engineers I knew treated it as a bureaucratic annoyance — extra checkboxes, more documentation, another compliance burden that would slow things down without making anything materially better. Then 2018 arrived, the regulation went live, and the industry discovered that data handling practices it had been comfortable with for a decade suddenly had hard legal teeth. Companies got fined. Products got redesigned. The phrase "privacy by design" went from nice-to-have to contractual requirement.

We're at a similar inflection point with AI regulation right now, except the surface area is larger, the jurisdictions are less coordinated, and the pace of both technology and regulation is faster. If you're building AI agent infrastructure — especially anything that deploys across geographies — you need to have a working mental model of what the regulatory landscape looks like, where it's heading, and what it means for how you build and operate your systems.

This isn't a legal document and I'm not a lawyer. What follows is a practitioner's reading of the major developments, informed by a lot of conversations with legal and compliance teams over the past year. Get a real lawyer to review anything that touches your specific deployment.

---

## The EU AI Act: the one everyone's talking about

The EU AI Act entered into force in August 2024, with a staggered implementation timeline that runs through 2027. It's the most comprehensive AI-specific regulation currently in force anywhere in the world, and because it applies to any AI system that's placed on the EU market or affects EU residents, it has global reach similar to GDPR.

The Act uses a risk-based classification system. Understanding which category your systems fall into is the first step.

**Unacceptable risk — prohibited.** These are outright banned in the EU. Social scoring by public authorities, subliminal manipulation, real-time biometric identification in public spaces (with narrow law enforcement exceptions), AI systems that exploit vulnerabilities of specific groups. If you're building AI governance infrastructure rather than AI applications, you're unlikely to be anywhere near this category.

**High risk.** This is the category that matters most for enterprise AI deployments. High-risk systems include AI used in critical infrastructure, educational assessment, employment decisions, access to essential services, law enforcement, and border control. High-risk systems must meet requirements around data governance, transparency, human oversight, accuracy and robustness, and cybersecurity before they can be deployed. They require conformity assessment — essentially an audit — and registration in a public EU database.

For AI agents operating in enterprise contexts: an AI agent that makes or influences decisions about employee performance, financial access, or essential service delivery is likely high-risk. An AI agent that does research, generates reports, or automates internal workflows is more likely to be limited risk or minimal risk.

**Limited risk.** Transparency obligations apply. If your AI system interacts with humans (chatbots, for example), users must know they're interacting with AI. Deepfakes must be labelled. This is about disclosure rather than capability restriction.

**Minimal risk.** AI that doesn't pose meaningful risks — spam filters, AI in video games, AI-generated marketing content — is essentially unregulated under the Act. You're free to deploy with no specific compliance obligations beyond general law.

**Where AI governance infrastructure sits.** A platform like euno — which doesn't make decisions itself but enforces policies around AI agent decisions — has an interesting regulatory position. The Act is primarily concerned with the AI system itself, not the governance infrastructure around it. But there are provisions about technical robustness and oversight of high-risk AI systems that point toward having exactly the kind of audit trail, policy enforcement, and human override capabilities that euno provides. The policy enforcement and tamper-evident audit discussed in [the SOC 2 post](./28-building-for-soc2.md) map directly to several EU AI Act Article 9 (risk management) and Article 12 (record-keeping) requirements.

**Foundation model provisions (GPAI rules).** The Act introduced specific provisions for general-purpose AI models — the Gemini, GPT, Claude class of systems. Providers of these models must maintain documentation, comply with copyright law, and (for high-impact models above a compute threshold) conduct adversarial testing and report incidents. This applies to model providers, not to organisations using those models via API, but it shapes what documentation and assurances you can demand from your LLM provider.

**Enforcement timeline.** The prohibited practices provisions went live in February 2025. GPAI rules and governance provisions apply from August 2025. High-risk system requirements for Annex I systems apply from August 2026. The full high-risk provisions for Annex III systems from August 2027. If you're building now for enterprise deployment, you have a window but it's not a long one.

---

## The UK's sector-based approach

The UK diverged from the EU's approach before the AI Act was finalised and has explicitly chosen not to enact cross-sector AI legislation (at least for now). Instead, the UK's approach is:

- Existing sectoral regulators (FCA for financial services, CQC for healthcare, Ofcom for communications) apply their existing frameworks to AI within their domains
- The AI Safety Institute (recently rebranded as the AI Security Institute) focuses on frontier model safety research
- A voluntary AI Code of Practice for providers of systems based on foundation models

What this means in practice: if you're deploying AI agents in financial services, you need to know what the FCA says about AI-assisted advice and automated decision-making — and the FCA has been active on this. If you're deploying in healthcare, the MHRA and CQC frameworks apply. There's no single "AI Act" to comply with, but the sector-specific requirements can be just as demanding.

The UK government has been considering a more formal regulatory framework, and the political situation means this could change. The AI Opportunities Action Plan published in 2025 signals intent to be "pro-innovation" but not unregulated. Worth watching.

For multinational deployments: if you're complying with the EU AI Act for EU operations, you're likely meeting or exceeding what UK regulators are currently asking for in most sectors. But don't assume equivalence — there are differences in the specific requirements, especially in financial services where the UK FCA has its own detailed AI guidance.

---

## The United States: federal fragmentation and state action

The US federal government has not enacted comprehensive AI legislation as of mid-2026. The executive order on AI safety from late 2023 (EO 14110) drove a wave of agency action — NIST published the AI Risk Management Framework (AI RMF), sector agencies published guidance, the Department of Commerce initiated regulatory proceedings — but there's no single federal AI Act equivalent.

What exists instead:

**NIST AI RMF (AI 100-1).** The AI Risk Management Framework is voluntary but widely referenced. It defines four core functions — Govern, Map, Measure, Manage — and provides a structured way to think about AI risk. The RMF is explicitly designed to complement sector-specific regulatory requirements. If you're engaging with US federal agencies or large enterprises that benchmark against NIST, familiarity with the RMF is worth the investment. The RMF's "GOVERN" function (building AI governance infrastructure, policies, and accountability mechanisms) is particularly relevant — it's describing the same problem space that euno addresses.

**Sector-specific guidance.** The Office of the Comptroller of the Currency (OCC) and Federal Reserve have published guidance on AI in banking. The FDA has pathways for AI/ML-based medical devices. The EEOC has issued guidance on AI in employment decisions. The FTC has signalled active interest in AI-enabled deceptive practices. Each of these has its own requirements, its own enforcement mechanisms, and its own interpretation of what "responsible AI" looks like in that sector.

**State-level legislation.** This is where the US picture gets complex. Illinois (AIEIA, effective January 2026), Colorado (SB24-205, effective February 2026), Texas (HB 1709), California (multiple bills including AB 2013 and SB 1047, though SB 1047 was vetoed) — states are moving independently. Some focus on automated employment decisions. Some focus on consumer protection. Some focus on transparency. Some focus on high-risk AI systems broadly.

For a platform operating in the US, the practical challenge is multi-state compliance. The state-level patchwork is developing faster than any harmonisation effort, and the requirements vary enough that a "lowest common denominator" approach is actually harder than it sounds. The Illinois AIEIA's requirements around bias audits for employment-related AI are quite specific, for example, and don't have a direct equivalent in most other states' frameworks.

**Federal legislative activity.** The AI LEAD Act, the SAFE Innovation AI Framework Act, and various other AI-related bills have moved through Congress at varying speeds. The political dynamic makes comprehensive federal legislation uncertain in timeline. It's more likely that we see sector-by-sector federal action (financial services AI regulation, healthcare AI regulation) before a comprehensive cross-sector law, if one comes at all.

---

## China: comprehensive regulation with specific requirements

China has been an active AI regulator and has moved faster than any other jurisdiction to issue specific, binding rules. The landscape includes:

**Recommendation Algorithm Regulations (2022).** Rules governing recommendation algorithms — the systems that decide what content users see. Operators must provide opt-out options, must not create "filter bubbles" based on personal characteristics, and must not use algorithms to engage in illegal price discrimination. For AI agents that include recommendation or ranking capabilities, this is directly applicable.

**Deep Synthesis Regulations (2023).** Covers AI-generated synthetic content — deepfakes, voice synthesis, generated images and video. Mandatory watermarking and disclosure requirements for synthetic content. Applicable to any system that generates or outputs synthetic media.

**Generative AI Regulations (August 2023).** This is the most directly relevant for LLM-based systems. Any service providing generative AI to users in China must:
- Register with the Cyberspace Administration of China (CAC) and conduct a security assessment
- Ensure training data quality and legitimacy (IP clearance for training data)
- Label AI-generated content
- Prevent outputs that include prohibited content (defined broadly)
- Maintain logs of user interactions

The registration and security assessment requirement is significant. It's not just guidelines — it's a permission requirement before you can deploy a generative AI service in China. The CAC's "Algorithmic Recommendation Filing" and "Generative AI Service Registration" processes are administrative hurdles that require dedicated compliance work.

**Interplay with data localisation.** China's Personal Information Protection Law (PIPL) and Data Security Law create significant constraints on cross-border data flows. If your AI agents process personal data of Chinese residents, or if interaction logs contain personal information, there are specific requirements around data localisation, consent, and security assessments for cross-border transfers. This is separate from the AI-specific regulations but intersects in practice — your audit logs may need to stay in China if they contain personal data.

---

## Canada: AIDA and PIPEDA evolution

Canada has been working on the Artificial Intelligence and Data Act (AIDA), which was introduced as part of Bill C-27 alongside updates to its privacy law. The legislative process has been slower than anticipated, but the framework's direction is clear.

AIDA would create a risk-based framework similar in structure to the EU AI Act, with:
- High-impact systems defined around contexts where decisions significantly affect individuals
- Obligations around mitigation measures, record-keeping, and human oversight for high-impact systems
- A prohibition on systems that "pose a serious risk of imminent harm"
- An AI and Data Commissioner with enforcement authority

As of early 2026, AIDA has not passed but remains in the legislative pipeline. Canadian organisations should plan for compliance rather than assuming it won't materialise. The direction of travel — risk-based, transparency-oriented, with specific high-impact system obligations — is consistent with what's happening elsewhere.

For AI deployments in Canada right now, the relevant frameworks are the existing PIPEDA (and its provincial equivalents), the Office of the Privacy Commissioner's guidance on AI and automated decision-making, and the Treasury Board of Canada's Directive on Automated Decision-Making (which applies to federal government use of AI). The federal directive is particularly detailed about the requirements for algorithmic impact assessments and the conditions under which human review is required.

---

## India: the emerging framework

India's Digital Personal Data Protection Act (DPDPA) came into force in 2023, establishing a data protection framework that will affect how AI systems process personal data of Indian residents. The Act is lighter on prescriptive requirements than GDPR but establishes principles and consent requirements that AI systems must respect.

Specific AI regulation is still developing. The Ministry of Electronics and IT (MeitY) has been consulting on frameworks for trustworthy AI and has published guidelines rather than hard regulation. The Indian government's broad approach has been to encourage AI development while working toward a regulatory framework, without the legislative urgency visible in the EU.

For multinational deployments: the DPDPA's consent and data fiduciary obligations are relevant for any AI system that processes personal data of Indian users. The specific AI regulations, when they arrive, are likely to reference the DPDPA framework.

---

## Brazil: the AI Bill and LGPD

Brazil's AI Bill (PL 2338/2023) has been working through the legislative process, modelled in part on the EU AI Act. It would establish:
- A risk-based classification (minimum, limited, high, excessive risk)
- Requirements for transparency, human oversight, and impact assessments for high-risk systems
- Data protection requirements referencing the existing LGPD (Brazil's GDPR-equivalent)

Brazil's existing LGPD already applies to AI systems processing personal data of Brazilian residents — the consent, purpose limitation, and data subject rights provisions are fully in force. The AI Bill layer on top of LGPD would add AI-specific requirements.

For Latin American deployments broadly: Brazil is the most developed AI regulatory jurisdiction in the region, and the direction of Brazilian legislation often influences other countries in the region over time.

---

## Japan and South Korea: guidelines and frameworks

Japan has taken a notably lighter regulatory approach. The AI Guidelines for Business (2024) from the Ministry of Economy, Trade and Industry (METI) focus on establishing principles and best practices rather than binding obligations. Japan's approach reflects a policy choice to prioritise AI adoption and not burden developers with compliance overhead.

South Korea has been more active on specific AI provisions — the AI Chatbot Transparency Act and various provisions in its Information and Communications Network Act apply to certain AI-mediated communications. South Korea also has specific AI requirements in financial services through the Financial Services Commission.

Both countries have signalled that more comprehensive regulation is under consideration, particularly as the EU AI Act creates pressure on trading partners to demonstrate equivalent standards for market access.

---

## What this means for how you build

After working through all of this, here's what I'd pull out as practical implications for AI governance platform builders.

**Document your risk classification.** Know where your AI systems fall in the EU AI Act risk taxonomy, and document that assessment. Even if your system is minimal-risk today, deployments in enterprise contexts can shift into high-risk territory when the decisions they influence cross certain thresholds (employment decisions, financial access, health-related outputs). Build the capability to produce risk classification documentation — it's going to be asked for.

**Audit trails aren't optional.** Every regulatory framework that specifies requirements for high-risk AI systems includes record-keeping provisions. The EU AI Act's Article 12 requires that high-risk systems keep logs that allow for monitoring and post-market surveillance. The US federal AI guidance consistently points to audit trails as a core risk management mechanism. Canada's federal Directive on Automated Decision-Making requires impact assessments and records of decisions. If you're building on a platform that doesn't produce a structured, verifiable audit trail, you're starting from behind. The tamper-evident audit infrastructure described in [the audit log post](../docs/blog/11-tamper-evident-audit-logs.md) and the SOC 2 mapping in the previous post are directly applicable here.

**Human oversight mechanisms are becoming mandatory.** The EU AI Act's high-risk provisions require that high-risk AI systems be designed to allow human oversight and intervention. That means kill-switches, not just conceptually but specifically: mechanisms that allow operators to stop the AI system quickly when needed. The gateway's kill-switch (described in [the reference monitor post](./10-tool-gateway-reference-monitor.md)) is exactly this — a fast-path mechanism to suspend all agent activity without needing to track down individual instances.

**Prepare for jurisdictional variation.** There is no single global standard, and there won't be one in the near term. An enterprise AI deployment in the EU, US, Canada, and India simultaneously faces four different frameworks with different requirements, different enforcement bodies, and different timelines. Building adaptable policy infrastructure — where you can adjust the conditions and constraints that govern agent behaviour without redeploying the enforcement stack — is much better than hard-coding compliance requirements. The YAML-based policy model that euno uses is specifically designed for this kind of adaptability.

**Foundation model transparency is becoming a due diligence requirement.** The EU AI Act's GPAI provisions require model providers to publish technical documentation. The US NIST AI RMF calls for transparency about training data, model architecture, and known limitations. As a deployer of AI using third-party models, you need to track this documentation for the models you use. When regulators ask "what do you know about the model you're using?", "I read the API docs" is not a sufficient answer.

**Data residency is intersecting with AI regulation.** China's requirements are the most explicit, but the intersection of data protection law and AI regulation is a global trend. If your AI agents process personal data — and most enterprise agents do — you need to think about where audit logs, interaction records, and inference data are stored relative to the data protection jurisdiction of the people whose data is involved.

---

## Where this is going

My best read of the trajectory, for whatever it's worth:

The EU AI Act is going to force the rest of the world's hand on high-risk AI classification. Companies building AI for global markets will need to meet EU AI Act requirements for their EU deployments, and the marginal cost of meeting similar requirements elsewhere drops significantly once you've built the EU compliance infrastructure. This is the GDPR dynamic playing out again: EU requirements effectively become a global floor.

The US will eventually pass some form of federal AI legislation, probably driven by a specific high-profile incident rather than by proactive policy design. The question is whether it happens before or after several states have locked in incompatible frameworks, creating the same multi-state compliance complexity that GDPR was partly designed to avoid (for European deployments, at least).

AI governance infrastructure — the stack that sits between AI agents and the resources they act on — is going to become a compliance requirement rather than a best practice. The question is whether you build it proactively, with control over how it works and how it fits your systems, or whether you build it reactively, in response to an audit finding or regulatory demand.

Regulators are also starting to ask the specific question that most AI governance frameworks haven't answered: not "do you have a policy?" but "do you have evidence that the policy was followed, in every case, for every agent decision?" The answer has to come from structured, verifiable records, not from assertions or sampled logs. Getting ahead of that question is why tamper-evident audit trails and policy enforcement at the decision layer matter as much as the regulatory frameworks say they do.

The laws will keep changing. The underlying requirement — demonstrate that your AI systems behave within defined constraints, and prove it — is stable. Build for the requirement, and the specific regulatory compliance tends to follow.
