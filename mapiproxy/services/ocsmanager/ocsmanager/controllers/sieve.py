import os, os.path
import string

sievePathBase = '/var/vmail/sieve'

# TODO unset OOF
def setOOF(vdomain, user, start, end, subject, message):
    path = _sievePath(vdomain, user)
    if os.path.isfile(path):
        raise Exception('TODO save old file')
    elif os.path.exists(path):
        raise Exception(path + "exists and it is not a regular file")
    else:
        userSieveDir = os.path.dirname(path)
        if not os.path.isdir(userSieveDir):
            if os.path.exists(userSieveDir):
                raise Exception(userSieveDir + " exists but is not a directory");

            domainSieveDir = os.path.dirname(userSieveDir)
            if not os.path.isdir(domainSieveDir):
                if os.path.exists(domainSieveDir):
                    raise Exception(domainSieveDir + " exists but is not a directory");
                elif not os.path.isdir(sievePathBase):
                    raise Exception('Base mail sieve directory ' + sievePathBase + 'does not exists')
                os.mkdir(domainSieveDir, 0755)

            os.mkdir(userSieveDir, 0700)

    script = _scriptForOOF(start, end, subject, message)
    # Sieve file mode?
    f = open(path, 'w')
    f.write(script)
    f.close()
    os.chmod(path, 0600)

# TODO: check if message has  " or '
def _scriptForOOF(start, end, subject, message):
    scriptTemplate = string.Template("""
require ["fileinto","vacation"];

vacation
:days 7
:subject $subject
"$message"
;
    """)

    return scriptTemplate.substitute(subject=subject, message=message)

def _sievePath(vdomain, user):
    return sievePathBase + '/' + vdomain + '/' + user + '/script'
