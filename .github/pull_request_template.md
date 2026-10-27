## What does this change?

<!-- One or two sentences. -->

## Security checklist

- [ ] No secrets, keys or passwords in the code or commit history
- [ ] New SQL uses `?` placeholders; new queries on `notes` filter by `owner_id`
- [ ] New pages use Jinja2 templates (autoescaping) and forms include `{{ csrf_field() }}`
- [ ] New dependencies are added to `requirements.in` and locked with hashes
- [ ] Tests added or updated (`tests/test_security.py` for security fixes)
- [ ] Security gate is green, or every finding is explained below

## Security findings and decisions

<!-- If you accept a risk, add it to security/policy.yml with a reason and an expiry date. -->
