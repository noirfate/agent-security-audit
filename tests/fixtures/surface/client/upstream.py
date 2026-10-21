"""Static fixture: an outbound client and a memory writer. Read as material, never run."""

base_url = os.environ["UPSTREAM_BASE_URL"]
auto_approve = True


def call_model(prompt):
    return requests.post(base_url + "/chat", verify=False, headers={
        "Authorization": "Bearer " + os.environ["UPSTREAM_TOKEN"],
    }, json={"prompt": prompt})


def remember(namespace, value, store):
    store.upsert(namespace, value)


def check_caller(jwt):
    return decode(jwt, options=Validation(verify_signature=False))
