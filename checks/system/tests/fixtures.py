"""MOCK policy and data only: never an operational approval record."""


def multifile_policy():
    return dict(check_id='FILE-01', description='(MOCK) synthetic approved policy for unit tests',
                severity='high', criteria=dict(files=[
                    dict(path='/etc/passwd', expected_uid=0, allowed_permission_bits='0644',
                         reference_gid=0, approval_status='approved'),
                    dict(path='/etc/shadow', expected_uid=None, allowed_permission_bits=None,
                         reference_gid=None, approval_status='pending')]))


def singlefile_policy():
    result = multifile_policy()
    result['criteria']['files'] = result['criteria']['files'][:1]
    return result
