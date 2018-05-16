import copy
import hashlib
import io
import json
import logging
import requests
import urllib

CHUNK_SIZE = 1024 * 128
MANIFEST_ACCEPT = 'application/vnd.docker.distribution.manifest.v2+json'
logger = logging.getLogger(__name__)


class Image:
    def __init__(self,registry,repo=None,tag=None,
                 cert=None,timeout=None):
        if (repo == None) and (tag == None):
            (registry,repo,tag) = split_fqn(registry)
        self.__registry = registry
        self.__repo     = repo
        self.__tag      = tag
        self.__manifest = None
        self.__config   = None
        self.__auth     = None
        self.__verify   = None
        self.__cert     = cert
        self.__timeout  = timeout


    def registry(self,registry=None):
        if registry:
            self.__registry = registry

        return self.__registry


    def repo(self,repo=None):
        if repo:
            self.__repo = repo

        return self.__repo


    def tag(self,tag=None):
        if tag:
            self.__tag = tag

        return self.__tag


    def cert(self,cert='<>'):
        if cert != '<>':
            self.__cert = cert

        return self.__cert


    def fqn(self):
        return '{}/{}:{}'.format(self.__registry,
                                 self.__repo,
                                 self.__tag)


    def manifest(self,manifest=None):
        if manifest:
            self.__manifest = manifest
        elif not self.__manifest:
            self.__manifest = get_manifest(self.__registry,
                                           self.__repo,
                                           self.__tag,
                                           auth=self.__auth,
                                           verify=self.__verify,
                                           cert=self.__cert,
                                           timeout=self.__timeout)
        return self.__manifest


    def put_manifest(self):
        return put_manifest(self.__registry,
                            self.__repo,
                            self.__tag,
                            self.__manifest,
                            auth=self.__auth,
                            verify=self.__verify,
                            cert=self.__cert,
                            timeout=self.__timeout)


    def put_config(self):
        return put_config(self.__registry,
                          self.__repo,
                          self.__config,
                          auth=self.__auth,
                          verify=self.__verify,
                          cert=self.__cert,
                          timeout=self.__timeout)


    def config(self,config=None):
        if config:
            self.__config = config
        elif not self.__config:
            manifest = self.manifest()
            config_digest = manifest['config']['digest']
            self.__config = get_config(self.__registry,
                                       self.__repo,
                                       config_digest,
                                       auth=self.__auth,
                                       verify=self.__verify,
                                       cert=self.__cert,
                                       timeout=self.__timeout)
        return self.__config


    def pull_data(self):
        try:
            self.manifest()
            self.config()
            return self
        except requests.exceptions.HTTPError as e:
            logging.error('Unable to access %s: %s - %s',
                          self.fqn(),e.response.reason,e.response.text)
            return None


    def uses_base(self,base):
        return image_uses_base(self.manifest(),base.manifest())


    def transfer_blobs(self,srcs,force_mirror=False):
        layers = []
        for src in srcs:
            self_layers = self.manifest()['layers']
            if ((src.registry() != self.__registry) or
                (src.repo()     != self.__repo)     or
                (force_mirror)):
                m = src.manifest()
                for layer in m['layers']:
                    if layer not in self_layers:
                        continue
                    digest = layer['digest']
                    logger.info('mirroring layer from %s/%s@%s -> %s/%s@%s',
                                src.registry(),src.repo(),digest,
                                self.__registry,self.__repo,digest)
                    mirror_blob(src.registry(),
                                src.repo(),
                                self.__registry,
                                self.__repo,
                                digest)
            else:
                m = src.manifest()
                for layer in m['layers']:
                    if layer not in self_layers:
                        continue
                    digest = layer['digest']
                    logger.info('mounting layer from %s/%s@%s -> %s/%s@%s',
                                src.registry(),src.repo(),digest,
                                self.__registry,self.__repo,digest)
                    mount_blob(self.__registry,
                               src.repo(),
                               self.__repo,
                               digest)


def build_manifest_url(registry,repo,tagOrDigest):
    url         = '{}/v2/{}/manifests/{}'
    repo        = urllib.parse.quote(repo)
    tagOrDigest = urllib.parse.quote(tagOrDigest)
    return url.format(registry,repo,tagOrDigest)


def build_blob_url(registry,repo,digest):
    url    = '{}/v2/{}/blobs/{}'
    repo   = urllib.parse.quote(repo)
    digest = urllib.parse.quote(digest)
    return url.format(registry,repo,digest)


def build_blob_upload_url(registry,repo):
    url  = '{}/v2/{}/blobs/uploads/'
    repo = urllib.parse.quote(repo)
    return url.format(registry,repo)


def build_blob_mount_url(registry,from_repo,to_repo,digest):
    url       = '{}/v2/{}/blobs/uploads/?mount={}&from={}'
    from_repo = urllib.parse.quote(from_repo)
    to_repo   = urllib.parse.quote(to_repo)
    digest    = urllib.parse.quote(digest)
    return url.format(registry,to_repo,digest,from_repo)


def get_manifest(registry,repo,tagOrDigest,auth=None,verify=None,cert=None,timeout=None):
    headers = {'Accept': MANIFEST_ACCEPT}
    url = build_manifest_url(registry,repo,tagOrDigest)
    res = requests.get(url,
                       headers=headers,
                       auth=auth,
                       verify=verify,
                       cert=cert,
                       timeout=timeout)
    res.raise_for_status()
    return res.json()


def put_manifest(registry,repo,tagOrDigest,manifest,
                 auth=None,verify=None,cert=None,timeout=None):
    url = build_manifest_url(registry,repo,tagOrDigest)
    headers = {'Accept': MANIFEST_ACCEPT,
               'Content-Type': MANIFEST_ACCEPT}
    data = json.dumps(manifest).encode()
    res = requests.put(url,
                       headers=headers,
                       data=data,
                       auth=auth,
                       verify=verify,
                       cert=cert,
                       timeout=timeout)
    res.raise_for_status()
    return res.headers['Location']


def blob_exists(registry,repo,digest,
                auth=None,verify=None,cert=None,timeout=None):
    url = build_blob_url(registry,repo,digest)
    res = requests.head(url)
    return res.status_code == 200


def get_blob(registry,repo,digest,auth=None,verify=None,cert=None,timeout=None):
    url = build_blob_url(registry,repo,digest)
    res = requests.get(url,
                       stream=True,
                       auth=auth,
                       verify=verify,
                       cert=cert,
                       timeout=timeout)
    res.raise_for_status()
    return res.raw


def put_blob_init(registry,repo,auth=None,verify=None,cert=None,timeout=None):
    url = build_blob_upload_url(registry,repo)
    res = requests.post(url,
                        auth=auth,
                        verify=verify,
                        cert=cert,
                        timeout=timeout)
    res.raise_for_status()
    return res.headers['Location']


def put_blob_finish(url,digest,auth=None,verify=None,cert=None,timeout=None):
    params = {'digest': digest}
    url += '&'+ urllib.parse.urlencode(params)
    headers = {'Content-Length': '0',
               'Content-Type': 'application/octet-stream'}
    res = requests.put(url,
                       headers=headers,
                       auth=auth,
                       verify=verify,
                       cert=cert,
                       timeout=timeout)
    res.raise_for_status()
    return res.headers['Location']


def put_blob(registry,repo,file_obj,chunk_size=CHUNK_SIZE,
             auth=None,verify=None,cert=None,timeout=None):
    sha256 = hashlib.sha256()
    url    = put_blob_init(registry,
                           repo,
                           auth=auth,
                           verify=verify,
                           cert=cert,
                           timeout=timeout)

    sent = 0
    buf  = file_obj.read(chunk_size)
    while buf:
        sha256.update(buf)

        buf_len = len(buf)
        content_range = '{}-{}'.format(sent,buf_len-1)
        headers = {'Content-Range': content_range,
                   'Content-Length': str(buf_len),
                   'Content-Type': 'application/octet-stream'}
        res = requests.patch(url,
                             headers=headers,
                             data=buf,
                             auth=auth,
                             verify=verify,
                             cert=cert,
                             timeout=timeout)
        res.raise_for_status()
        url   = res.headers['Location']
        sent += buf_len
        buf   = file_obj.read(chunk_size)

    digest = 'sha256:' + sha256.hexdigest()
    return put_blob_finish(url,
                           digest,
                           auth=auth,
                           verify=verify,
                           cert=cert,
                           timeout=timeout)


def get_config(registry,repo,digest,auth=None,verify=None,cert=None,timeout=None):
    f = get_blob(registry,repo,digest,auth,verify,cert,timeout)
    return json.load(f)


def put_config(registry,repo,config,auth=None,verify=None,cert=None,timeout=None):
    config_blob = json.dumps(config).encode()
    f = io.BytesIO(config_blob)
    return put_blob(registry,repo,f,auth=auth,verify=verify,cert=cert,timeout=timeout)


def mount_blob(registry,from_repo,to_repo,digest,
               auth=None,verify=None,cert=None,timeout=None):
    url = build_blob_mount_url(registry,from_repo,to_repo,digest)
    headers = {'Accept': MANIFEST_ACCEPT}
    res = requests.post(url,
                        headers=headers,
                        auth=auth,
                        verify=verify,
                        cert=cert,
                        timeout=timeout)
    res.raise_for_status()
    return res.headers['Location']


def mirror_blob(from_reg,from_repo,to_reg,to_repo,digest,
                auth=None,verify=None,cert=None,timeout=None):
    rv = blob_exists(to_reg,to_repo,digest,auth,verify,cert,timeout)
    if rv:
        logging.info('Skipping blob mirror: %s/%s@%s already exists',
                     to_reg,to_repo,digest)
        return
    f = get_blob(from_reg,
                 from_repo,
                 digest,
                 auth=auth,
                 verify=verify,
                 cert=cert,
                 timeout=timeout)
    put_blob(to_reg,
             to_repo,
             f,
             auth=auth,
             verify=verify,
             cert=cert,
             timeout=timeout)


def patch_list(src,old_base,new_base):
    new  = copy.deepcopy(new_base)
    new += src[len(old_base):]
    return new


def patch_config(src,old_base,new_base):
    new = copy.deepcopy(src)

    for key in old_base['config']['Labels']:
        del new['config']['Labels'][key]
    new['config']['Labels'].update(new_base['config']['Labels'])

    new['history'] = patch_list(src['history'],
                                old_base['history'],
                                new_base['history'])

    new['rootfs']['diff_ids'] = patch_list(src['rootfs']['diff_ids'],
                                           old_base['rootfs']['diff_ids'],
                                           new_base['rootfs']['diff_ids'])

    return new


def patch_manifest(src,old_base,new_base,config_digest,config_len):
    new = copy.deepcopy(src)

    new['layers'] = patch_list(src['layers'],
                               old_base['layers'],
                               new_base['layers'])

    new['config']['digest'] = config_digest
    new['config']['size']   = config_len

    return new


def image_uses_base(img,base):
    img_layers  = img['layers']
    base_layers = base['layers']
    for i in range(0,len(base_layers)):
        if img_layers[i]['digest'] != base_layers[i]['digest']:
            return False
    return True


def rebase(orig_img,orig_base,new_base,
           labels=[]):
    if not orig_img.uses_base(orig_base):
        msg = '{} not based on {}'.format(orig_img.fqn(),orig_base.fqn())
        raise ValueError(msg)

    config = patch_config(orig_img.config(),
                          orig_base.config(),
                          new_base.config())

    for k,v in labels:
        config['config']['Labels'][k] = v

    config_blob   = json.dumps(config).encode()
    config_len    = len(config_blob)
    config_digest = 'sha256:' + hashlib.sha256(config_blob).hexdigest()

    manifest = patch_manifest(orig_img.manifest(),
                              orig_base.manifest(),
                              new_base.manifest(),
                              config_digest,
                              config_len)

    new_img = copy.deepcopy(orig_img)

    new_img.config(config)
    new_img.manifest(manifest)

    return new_img


def split_fqn(fqn):
    if not (fqn.startswith('http://') or fqn.startswith('https://')):
        fqn = 'http://' + fqn
    url = urllib.parse.urlparse(fqn)

    registry = url.scheme + '://' + url.netloc

    rv = url.path.rsplit('@',1)
    if len(rv) == 2:
        repo     = rv[0].strip('/')
        digest   = rv[1]
        return (registry,repo,digest)

    rv = url.path.rsplit(':',1)
    if len(rv) == 2:
        repo = rv[0].strip('/')
        tag  = rv[1]
        return (registry,repo,tag)

    return None
