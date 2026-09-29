---
name: ward-no-trigger-password-meter
runs: 3
max_turns: 20
timeout_seconds: 300
allowed_tools: [Read, Glob, Grep, Skill]
---

I am building the signup form for our web app and I want a password strength
meter — a bar that fills up as the user types and shows what is missing. What
is a good client-side way to estimate entropy and map it to a score? Is
zxcvbn still the library people use for this, or is there something better
these days?
