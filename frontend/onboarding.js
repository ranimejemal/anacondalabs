/**
 * AegisLab - onboarding.js
 * ==========================
 * A short, skippable first-run walkthrough. Shown once (tracked via
 * localStorage — this is a real desktop app, not a hosted web page, so
 * localStorage here is just persisting a local UI preference, same as any
 * native app's "don't show this again" setting).
 *
 * Deliberately short (4 steps) and entirely dismissible at any point —
 * the goal is orienting a first-time user in 20 seconds, not a forced tour.
 */

const ONBOARDING_STORAGE_KEY = "aegislab_onboarding_seen_v1";

const ONBOARDING_STEPS = [
  {
    title: "Welcome to AegisLab",
    body: "AegisLab runs automated, OWASP-aligned security checks against an API you configure — either a live API (import an OpenAPI spec, or add endpoints manually) or a source code .zip (static scan, no running API needed).",
  },
  {
    title: "Only scan what you're authorized to test",
    body: "Before any live scan runs, you'll need to check a consent box confirming you own or are authorized to test the target. This isn't just a formality — running security scans against systems without authorization can have real legal consequences. Static (source code) scans don't need this, since nothing is sent over the network.",
  },
  {
    title: "Findings, scored and explained",
    body: "Every finding maps to a specific OWASP API Security Top 10 category, with a plain-language impact and recommendation. The Top Priority Fixes panel surfaces the 5 most severe issues first, several with a ready-to-paste code snippet.",
  },
  {
    title: "AI fixes are optional",
    body: "Sign in (optional, top-right) to unlock AI-generated fix suggestions on top of the built-in recommendations — free accounts get suggestions as text, premium accounts get one-click auto-apply on uploaded source. Scanning itself never requires an account.",
  },
];

let _onboardingStep = 0;

function initOnboarding() {
  if (localStorage.getItem(ONBOARDING_STORAGE_KEY)) return; // already seen

  _onboardingStep = 0;
  _renderOnboardingStep();
  document.getElementById("onboardingBackdrop").classList.add("open");

  document.getElementById("onboardingNext").addEventListener("click", () => {
    _onboardingStep += 1;
    if (_onboardingStep >= ONBOARDING_STEPS.length) {
      _closeOnboarding();
    } else {
      _renderOnboardingStep();
    }
  });
  document.getElementById("onboardingSkip").addEventListener("click", _closeOnboarding);
}

function _renderOnboardingStep() {
  const step = ONBOARDING_STEPS[_onboardingStep];
  document.getElementById("onboardingStepContent").innerHTML =
    `<h3>${step.title}</h3><p>${step.body}</p>`;

  const dots = ONBOARDING_STEPS.map((_, i) =>
    `<span class="${i === _onboardingStep ? "active" : ""}"></span>`
  ).join("");
  document.getElementById("onboardingDots").innerHTML = dots;

  const isLast = _onboardingStep === ONBOARDING_STEPS.length - 1;
  document.getElementById("onboardingNext").textContent = isLast ? "Get started" : "Next";
}

function _closeOnboarding() {
  document.getElementById("onboardingBackdrop").classList.remove("open");
  localStorage.setItem(ONBOARDING_STORAGE_KEY, "1");
}

// Exposed so a future "Show tutorial again" settings option can call it
// without needing to clear localStorage manually.
window.aegisOnboarding = {
  show: () => { localStorage.removeItem(ONBOARDING_STORAGE_KEY); initOnboarding(); },
};
