#!/usr/bin/env python3
    def format_name(self, max_len=30) -> None:
        name = self.name
        for word in BANNED_WORDS:
            name = name.replace(word, '*'*len(word))
        if len(name) > max_len:
            name = name[:max_len]+'...'
        # Merged from #35
        if NAME_NO_FLAGS:
            # 地区旗帜符号 A - Z 对应 127462 - 127487
            name = ''.join([
                chr(ord(c)-127462+ord('A')) if 127462<=ord(c)<=127487 else c
                for c in name
            ])
        if NAME_SHOW_TYPE:
            if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                tp = self.type.upper()
            else:
                tp = self.type.title()
            name = f'[{tp}] ' + name
        if name in Node.gNames:
            i = 0
            new = name
            while new in Node.gNames:
                i += 1
                new = f"{name} #{i}"
            name = new
        self.data['name'] = name

    @property
    def isfake(self) -> bool:
        if STOP: return False
        try:
            if 'server' not in self.data: return True
            if '.' not in self.data['server']: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            # TODO: Fake UUID
            # if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            #     return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                # That's not designed for China
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    @property
    def url(self) -> str:
        handler: Optional[Callable[[Node.DATA_TYPE], str]] = \
                getattr(self, '_url_'+self.type, None)
        if handler: return handler(self.data)
        else: raise UnsupportedType(self.type)

    def _url_vmess(self, data: DATA_TYPE) -> str:
        v = VMESS_TEMPLATE.copy()
        for key, val in data.items():
            if key in CLASH2VMESS:
                v[CLASH2VMESS[key]] = val
        if v['net'] == 'ws':
            if 'ws-opts' in data:
                try:
                    v['host'] = data['ws-opts']['headers']['Host']
                except KeyError: pass
                if 'path' in data['ws-opts']:
                    v['path'] = data['ws-opts']['path']
        elif v['net'] == 'h2':
            if 'h2-opts' in data:
                if 'host' in data['h2-opts']:
                    v['host'] = ','.join(data['h2-opts']['host'])
                if 'path' in data['h2-opts']:
                    v['path'] = data['h2-opts']['path']
        elif v['net'] == 'grpc':
            if 'grpc-opts' in data:
                if 'grpc-service-name' in data['grpc-opts']:
                    v['path'] = data['grpc-opts']['grpc-service-name']
        if data.get('tls'):
            v['tls'] = 'tls'
        return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

    def _url_ss(self, data: DATA_TYPE) -> str:
        passwd = b64encodes_safe(data['cipher']+':'+data['password'])
        return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"

    def _url_ssr(self, data: DATA_TYPE) -> str:
        ret = (':'.join([str(data[_]) for _ in ('server','port',
                                    'protocol','cipher','obfs')]) +
                b64encodes_safe(data['password']) +
                f"remarks={b64encodes_safe(data['name'])}")
        for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
            if k in data:
                ret += '&'+urlk+'='+b64encodes_safe(data[k])
        return "ssr://"+ret

    def _url_trojan(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'sni' in data:
            ret += f"sni={data['sni']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_vless(self, data: DATA_TYPE) -> str:
        passwd = quote(data['uuid'])
        name = quote(data['name'])
        ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
        if 'skip-cert-verify' in data:
            ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
        if 'servername' in data:
            ret += f"sni={data['servername']}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'network' in data:
            if data['network'] == 'grpc':
                ret += f"type=grpc&"
                try:
                    ret += f"serviceName={data['grpc-opts']['grpc-service-name']}&"
                except KeyError: pass
            elif data['network'] == 'ws':
                ret += f"type=ws&"
                if 'ws-opts' in data:
                    try:
                        ret += f"host={data['ws-opts']['headers']['Host']}&"
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        ret += f"path={data['ws-opts']['path']}"
        if 'flow' in data:
            flow: str = data['flow']
            if flow.endswith('!'):
                ret += f"flow={flow[:-1]}&"
            else: ret += f"flow={flow}-udp443&"
        if 'client-fingerprint' in data:
            ret += f"fp={data['client-fingerprint']}&"
        if data.get('tls'):
            ret += f"security=tls&"
        elif 'reality-opts' in data:
            opts: Dict[str, str] = data['reality-opts']
            ret += f"security=reality&pbk={opts.get('public-key','')}&sid={opts.get('short-id','')}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url_hysteria2(self, data: DATA_TYPE) -> str:
        passwd = quote(data['password'])
        name = quote(data['name'])
        ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
        if 'ports' in data:
            ret += ','+data['ports']
        ret += '?'
        if 'skip-cert-verify' in data:
            ret += f"insecure={int(data['skip-cert-verify'])}&"
        if 'alpn' in data:
            ret += f"alpn={quote(','.join(data['alpn']))}&"
        if 'fingerprint' in data:
            ret += f"fp={data['fingerprint']}&"
        for k in ('sni', 'obfs', 'obfs-password'):
            if k in data:
                ret += f"{k}={data[k]}&"
        ret = ret.rstrip('&')+'#'+name
        return ret

    def _url__legacy(self, data: DATA_TYPE) -> str:
        tp = 'https' if self.type == 'http' and data.get('tls') else self.type
        part = ''
        if 'username' in data:
            part += data['username']
        if 'password' in data:
            part += ':' + data['password']
        if part: part += '@'
        return f"{tp}://{part}{data['server']}:{data['port']}"

    _url_http = _url__legacy
    _url_https = _url__legacy
    _url_socks5 = _url__legacy

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret: del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            # 'alpn' is not a slice
            ret['alpn'] = ret['alpn'].replace(' ','').split(',')
        # A temporary fix for mihomo-party's `invalid REALITY short ID` error.
        if 'reality-opts' in ret and 'short-id' in ret['reality-opts']:
            ret['reality-opts']['short-id'] = '!!str '+ret['reality-opts']['short-id']
        return ret

    def supports_clash(self, meta=False) -> bool:
        if self.isfake: return False
        if 'obfs' in self.data and 'obfs-password' not in self.data:
            return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        elif not meta: return False
        else: return True
        # Vmess / SS / SSR
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            # A quick fix for #2
            self.data['tls'] = True
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        if self.data['cipher'] not in supported: return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                    and not self.data['plugin-opts']['mode']: return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return False
        return True

    def supports_meta(self) -> bool:
        return self.supports_clash(meta=True)

    def supports_ray(self) -> bool:
        if self.isfake: return False
        # if self.type == 'ss':
        #     if 'plugin' in self.data and self.data['plugin']: return False
        # elif self.type == 'ssr':
        #     return False
        if self.type == 'socks5' and self.data.get('tls'):
            return False
        return True

class Source():
    def __init__(self, url: Union[str, function]) -> None:
        self.url_source: Union[str, function, None]
        if isinstance(url, function):
            self.url: str = "dynamic://"+url.__name__
            self.url_source = url
        elif url.startswith('+'):
            self.url_source = url
            self.date = datetime.datetime.now()# + datetime.timedelta(days=1)
            self.gen_url()
        else:
            self.url: str = url
            self.url_source = None
        self.content: Union[str, Iterable[str], int] = None
        self.sub: Union[List[str], List[Dict[str, str]]] = None
        self.cfg: Dict[str, Any] = {}
        self.exc_queue: List[str] = []

    def gen_url(self):
        assert isinstance(self.url_source, str)
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    def get(self, depth=2) -> None:
        if self.content: return
        try:
            if self.url.startswith("dynamic:"):
                assert isinstance(self.url_source, function)
                self.content: Union[str, Iterable[str]] = self.url_source()
            else:
                global session
                if '#' in self.url:
                    segs = self.url.split('#')
                    self.cfg = dict([_.split('=',1) for _ in segs[-1].split('&')])
                    if 'max' in self.cfg:
                        try:
                            self.cfg['max'] = int(self.cfg['max'])
                        except ValueError:
                            self.exc_queue.append("最大节点数限制不是整数！")
                            del self.cfg['max']
                    if 'ignore' in self.cfg:
                        self.cfg['ignore'] = [_ for _ in self.cfg['ignore'].split(',') if _.strip()]
                    self.url = '#'.join(segs[:-1])
                with session.get(resolveRelFile(self.url), stream=True) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t"+self.url
                            self.exc_queue.append(exc)
                            self.get(depth-1)
                        else:
                            self.content = r.status_code
                        return
                    self.content = self._download(r)
        except KeyboardInterrupt: raise
        except requests.exceptions.RequestException:
            self.content = -1
        except:
            self.content = -2
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            self.exc_queue.append(exc)
        else:
            self.parse()

    def _download(self, r: requests.Response) -> str:
        content = bytes()
        tp = None
        pending = None
        early_stop = False
        for chunk in r.iter_content():
            if early_stop: pending = None; break
            chunk: bytes
            if tp == 'sub':
                content += chunk
                continue
            if pending != None:
                chunk = pending + chunk
                pending = None
            lines = chunk.splitlines()
            if lines and lines[-1] and chunk.endswith(lines[-1]):
                pending = lines.pop()
            while lines:
                lineb = lines.pop(0)
                line = lineb.decode().replace('\\r','').rstrip()
                if not line: continue
                if not tp:
                    if ': ' in line:
                        if line.count(': ') == 1 and line.isalpha():
                            tp = 'yaml'
                    elif line[0] == '#': pass
                    else: tp = 'sub'
                if tp == 'yaml':
                    if content:
                        if line in ("proxy-groups:", "rules:", "script:"):
                            early_stop=True; break
                        content += lineb + b'\n'
                    elif line == "proxies:":
                        content = lineb + b'\n'
                elif tp == 'sub':
                    content = chunk
                    pending = None
                    break
        if pending != None: content += pending
        try:
            ret = content.decode()
        except UnicodeDecodeError:
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            self.exc_queue.append(exc)
            ret = content.decode('ignore')
        return ret

    def parse(self):
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    # Clash config
                    config = yaml.full_load(text.replace("!<str>","!!str"))
                    sub = config['proxies']
                elif '://' in text:
                    # V2Ray raw list
                    sub = text.strip().splitlines()
                else:
                    # V2Ray Sub
                    sub = b64decodes(text.strip()).strip().splitlines()
            elif not isinstance(text, (list, tuple)):
                sub = list(text)
            else: sub = text # 动态节点抓取后直接传入列表

            if 'max' in self.cfg and len(sub) > self.cfg['max']:
                self.exc_queue.append(f"此订阅有 {len(sub)} 个节点，最大限制为 {self.cfg['max']} 个，忽略此订阅。")
                self.sub = []
            elif sub and 'ignore' in self.cfg:
                if isinstance(sub[0], str):
                    self.sub = [_ for _ in sub if _.split('://', 1)[0] not in self.cfg['ignore']]
                elif isinstance(sub[0], dict):
                    self.sub = [_ for _ in sub if _.get('type', '') not in self.cfg['ignore']] #type:ignore
                else: self.sub = sub
            else: self.sub = sub
        except KeyboardInterrupt: raise
        except: self.exc_queue.append(
                "在解析 '"+self.url+"' 时发生错误：\n"+traceback.format_exc())

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]):
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = __class__()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str):
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]):
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here: ret.append(name)
            else: ret.extend([_+'.'+name for _ in child.get()])
        return ret

def extract(url: str) -> Union[Set[str], int]:
    global session
    res = session.get(url)
    if res.status_code != 200: return res.status_code
    urls: Set[str] = set()
    mark = '#'+url.split('#', 1)[1] if '#' in url else ''
    for line in res.text.strip().splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.add(line+mark)
    return urls

merged: Dict[int, Node] = {}
unknown: Set[str] = set()
used: Dict[int, Dict[int, str]] = {}
def merge(source_obj: Source, sourceId=-1):
    global merged, unknown
    sub = source_obj.sub
    if not sub: print("空订阅，跳过！", end='', flush=True); return
    for p in sub:
        if isinstance(p, str) and '://' not in p: continue
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p)
        except: traceback.print_exc()
        else:
            n.format_name()
            Node.gNames.add(n.data['name'])
            hashn = hash(n)
            if hashn not in merged:
                merged[hashn] = n
            else:
                merged[hashn].update(n)
            if hashn not in used:
                used[hashn] = {}
            used[hashn][sourceId] = n.name

def raw2fastly(url: str) -> str:
    if not LOCAL: return url
    url: Union[str, List[str]]
    if url.startswith("https://raw.githubusercontent.com/"):
        # url = url[34:].split('/')
        # url[1] += '@'+url[2]
        # del url[2]
        # url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
        # return url
        return "https://ghproxy.cfd/"+url
    return url

def merge_adblock(adblock_name: str, rules: Dict[str, str]):
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    unblock: Set[str] = set()
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(resolveRelFile(url))
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] in '!#': continue
            elif line[:2] == '@@':
                unblock.add(line.split('^')[0].strip('@|^'))
            elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                            (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))

    for url in ABFWHITE:
        url = raw2fastly(url)
        try:
            res = session.get(resolveRelFile(url))
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if not line or line[0] == '!': continue
            else: unblock.add(line.split('^')[0].strip('|^'))

    domain_root = DomainTree()
    domain_keys: Set[str] = set()
    for domain in blocked:
        if '/' in domain: continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.','').isdigit(): # IP
            for seg in segs: # '223.73.212.020' is not valid
                if not seg: break
                if seg[0] == '0' and seg != '0': break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)
    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain: break
        else: rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    print(f"共有 {len(rules)} 条规则")

def main():
    global merged, FETCH_TIMEOUT, ABFURLS, AUTOURLS, AUTOFETCH
    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if DEBUG_NO_NODES:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        sources = []
    if DEBUG_NO_DYNAMIC:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已选择不抓取动态节点 !!!")
        AUTOURLS = AUTOFETCH = []
    print("正在生成动态链接...")
    for auto_fun in AUTOURLS:
        print("正在生成 '"+auto_fun.__name__+"'... ", end='', flush=True)
        try: url = auto_fun()
        except requests.exceptions.RequestException: print("失败！")
        except: print("错误：");traceback.print_exc()
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                print("成功！")
            else: print("跳过！")
    print("正在整理链接...")
    sources_final: Union[Set[str], List[str]] = set()
    airports: Set[str] = set()
    for source in sources:
        if source == 'EOF': break
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    if airports:
        print("正在抓取机场列表...")
        for sub in airports:
            print("合并 '"+sub+"'... ", end='', flush=True)
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                print("正在退出...")
                break
            except requests.exceptions.RequestException:
                print("合并失败！")
            except: traceback.print_exc()
            else:
                if isinstance(res, int):
                    print(res)
                else:
                    for url in res:
                        sources_final.add(url)
                    print("完成！")

    print("正在整理链接...")
    sources_final = list(sources_final)
    sources_final.sort()
    sources_obj = [Source(url) for url in (sources_final + AUTOFETCH)]

    print("开始抓取！")
    threads = [threading.Thread(target=_.get, daemon=True) for _ in sources_obj]
    for thread in threads: thread.start()
    for i in range(len(sources_obj)):
        try:
            for t in range(1, FETCH_TIMEOUT[0]+1):
                print("抓取 '"+sources_obj[i].url+"'... ", end='', flush=True)
                try: threads[i].join(timeout=FETCH_TIMEOUT[1])
                except KeyboardInterrupt:
                    print("正在退出...")
                    FETCH_TIMEOUT = (1, 0)
                    break
                if not threads[i].is_alive(): break
                print(f"{5*t}s")
            if threads[i].is_alive():
                print("超时！")
                continue
            res = sources_obj[i].content
            if isinstance(res, int):
                if res < 0: print("抓取失败！")
                else: print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(sources_obj[i], sourceId=i)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
            for exc in sources_obj[i].exc_queue:
                print(exc)
            sources_obj[i].exc_queue = []
        except KeyboardInterrupt:
            print("正在退出...")
            break

    if STOP:
        merged = {}
        for nid, nd in enumerate(STOP_FAKE_NODES.splitlines()):
            merged[nid] = Node(nd)

    elif NAME_SHOW_SRC:
        for hashp, p in merged.items():
            if hashp in used:
                src = ','.join([str(_) for _ in sorted(list(used[hashp]))])
                p.data['name'] = src+'|'+p.data['name']

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    for hashp, p in merged.items():
        try:
            if p.supports_ray():
                try:
                    txt += p.url + '\n'
                except UnsupportedType as e:
                    print(f"不支持的类型：{e}")
            else: unsupports += 1
        except: traceback.print_exc()
    for p in unknown:
        txt += p+'\n'
    print(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共",
            len(merged)+len(unknown),f"个。{unsupports} 个节点不被 V2Ray 支持。")

    with open("list_raw.txt", 'w', encoding="utf-8") as f:
        f.write(txt)
    with open("list.txt", 'w', encoding="utf-8") as f:
        f.write(b64encodes(txt))
    print("写出完成！")

    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)

    rules: Dict[str, str] = {}
    if DEBUG_NO_ADBLOCK:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
    else:
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)

    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    ctg_nodes_meta: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}
    try:
        snip_conf = conf['NoMoreWalls']
    except KeyError:
        print("未设置片段配置：", file=sys.stderr)
        traceback.print_exc()
    else:
        del conf['NoMoreWalls']
        print("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories:
            ctg_nodes[ctg] = []
            ctg_nodes_meta[ctg] = []
        for node in merged.values():
            if node.supports_meta():
                ctgs: List[str] = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    if node.supports_clash():
                        ctg_nodes[ctgs[0]].append(node.clash_data)
                    ctg_nodes_meta[ctgs[0]].append(node.clash_data)
        for ctg, proxies in ctg_nodes.items():
            with open("snippets/nodes_"+ctg+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)
        for ctg, proxies in ctg_nodes_meta.items():
            with open("snippets/nodes_"+ctg+".meta.yml", 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)

    print("正在写出 Clash & Meta 订阅...")
    keywords: List[str] = []
    suffixes: List[str] = []
    match_rule = None
    for rule in conf['rules']:
        rule: str
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == 'DOMAIN-KEYWORD':
                keywords.append(rargument)
            elif rtype == 'DOMAIN-SUFFIX':
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ','+rresolve
        else: print("规则 '"+rule+"' 无法被解析！"); continue
        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                print(rargument, "已被 KEYWORD", kwd, "命中")
                break
        else:
            for sfx in suffixes:
                if ('.'+rargument).endswith('.'+sfx) and sfx != rargument:
                    print(rargument, "已被 SUFFIX", sfx, "命中")
                    break
            else:
                k = rtype+','+rargument
                if k not in rules:
                    rules[k] = rpolicy
    conf['rules'] = [','.join(_) for _ in rules.items()]+[match_rule]

    # Clash & Meta
    global_fp: Optional[str] = conf.get('global-client-fingerprint', None)
    proxies: List[Node.DATA_TYPE] = []
    proxies_meta: List[Node.DATA_TYPE] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash: Union[Set[str], List[str]] = set()
    names_clash_meta: Union[Set[str], List[str]] = set()
    for p in merged.values():
        if p.supports_meta():
            if ('client-fingerprint' in p.data and
                    p.data['client-fingerprint'] == global_fp):
                del p.data['client-fingerprint']
            proxies_meta.append(p.clash_data)
            names_clash_meta.add(p.data['name'])
            if p.supports_clash():
                proxies.append(p.clash_data)
                names_clash.add(p.data['name'])
    names_clash = list(names_clash)
    names_clash_meta = list(names_clash_meta)
    conf_meta = copy.deepcopy(conf)

    # Clash
    conf['proxies'] = proxies
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload: disp['proxies'] = ['REJECT']
                else: disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    try:
        dns_mode: Optional[str] = conf['dns']['enhanced-mode']
    except:
        dns_mode: Optional[str] = None
    else:
        conf['dns']['enhanced-mode'] = 'fake-ip'
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))
    with open("snippets/nodes.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies}, allow_unicode=True).replace('!!str ',''))

    # Meta
    conf = conf_meta
    conf['proxies'] = proxies_meta
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash_meta
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes_meta.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload: disp['proxies'] = ['REJECT']
                else: disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    if dns_mode:
        conf['dns']['enhanced-mode'] = dns_mode
    with open("list.meta.yml", 'w', encoding="utf-8") as f:
        f.write(datetime.datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n'))
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))
    with open("snippets/nodes.meta.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': proxies_meta}, allow_unicode=True).replace('!!str ',''))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values(): snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy: rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/"+name+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: out += f"{len(source.sub)}"
        except: out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    open("list_result.csv",'w').write(out)

    print("写出完成！")

if __name__ == '__main__':
    from dynamic import AUTOURLS, AUTOFETCH
    main()
