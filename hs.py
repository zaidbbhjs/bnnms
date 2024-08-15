try:
    import os
    import requests
    from user_agent import generate_user_agent
    from hashlib import md5
    import random
    from bs4 import BeautifulSoup
    import time    
    from secrets import token_hex
    from datetime import datetime
    from uuid import uuid4
except:
    import os
    os.system('pip install requests')
    os.system('pip install user_agent')
    os.system('pip install bs4')
    os.system('pip install uuid')
    import requests
    from user_agent import generate_user_agent
    from hashlib import md5
    import random
    from bs4 import BeautifulSoup
    import time
    from datetime import datetime
    from secrets import token_hex
    from uuid import uuid4
from auth import Gorgon,Argus,Ladon
from urllib.parse import urlencode
import time
def sign(params, payload: str = None, sec_device_id: str = "", cookie: str or None = None, aid: int = 1233, license_id: int = 1611921764, sdk_version_str: str = "v04.04.05-ov-android", sdk_version: int = 134744640, platform: int = 0, unix: int = None):
        x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload != None else None
        if not unix: unix = int(time.time())
    
        return Gorgon(params, unix, payload, cookie).get_value() | { 
        "x-ladon" : Ladon.encrypt(unix, license_id, aid),
        "x-argus"   : Argus.get_sign(params, x_ss_stub, unix,
                platform        = platform,
                aid             = aid,
                license_id      = license_id,
                sec_device_id   = sec_device_id,
                sdk_version     = sdk_version_str, 
                sdk_version_int = sdk_version
            )
        }
def base_params():
            
            return {
            "passport-sdk-version": "19",
            "iid": '7318518857994389254',
            "device_id": '7318517321748022790',
            "ac": "wifi",
            "channel": "googleplay",
            "aid": "1233",
            "app_name": "musical_ly",
            "version_code": "300904",
            "version_name": "30.9.4",
            "device_platform": "android",
            "os": "android",
            "ab_version": "30.9.4",
            "ssmix": "a",
            "device_type": "ASUS_Z01QD",
            "device_brand": "Asus",
            "language": "en",
            "os_api": "28",
            "os_version": "9",
            "openudid": "704713c0da01388a",
            "manifest_version_code": "2023009040",
            "resolution": "1600*900",
            "dpi": "300",
            "update_version_code": "2023009040",
            "_rticket": "1692845349183",
            "is_pad": "0",
            "current_region": "BE",
            "app_type": "normal",
            "sys_region": "US",
            "mcc_mnc": "20610",
            "timezone_name": "Asia/Shanghai",
            "residence": "BE",
            "app_language": "en",
            "carrier_region": "BE",
            "ac2": "wifi",
            "uoo": "0",
            "op_region": "BE",
            "timezone_offset": "28800",
            "build_number": "30.9.4",
            "host_abi": "arm64-v8a",
            "locale": "en",
            "region": "US",
            "ts": "1692845349",
            "cdid": "60c2140f-c112-491a-8c93-183fd1ea8acf",
            "support_webview": "1",
            "okhttp_version": "4.1.120.34-tiktok",
            "use_store_region_cookie": "1"
        }
from flask import Flask
app=Flask(__name__)
@app.route('/')
def CheckTik(email):
            ticket=(sign(urlencode(base_params()))['x-ss-req-ticket'])
            khrono=(sign(urlencode(base_params()))['x-khronos'])
            gorgon=(sign(urlencode(base_params()))['x-gorgon'])
            ladon=(sign(urlencode(base_params()))['x-ladon'])
            argus=(sign(urlencode(base_params()))['x-argus'])
            import requests
            import json
            H3 = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Accept": "*/*",
    "Content-Type": "application/x-www-form-urlencoded"
}
            D3 = {
    "magic": 538969122,
    "version": 1,
    "dataType": 8,
    "strData": "3QRQryRpfSdprzJqnh62HO8QcrfJFxwSeWX1EuUvE+0mErH7A9RMd/OGDfBMBCRV9ZOAmTMH3YMc7hnU1mAYJ0LxvfAFUZWxKDMtoTcVIHWTs9aeP/PePd1YQGAFzcLtpHDdsaPglYF0zjef1W5/1v7u4Snk8+lIA5VM5KzkYsDEhSOyZn5v/KJiuCt8ZH23HgBuJi77+tKyVZSvNlOnKNqZIV8kf7Atgs7rmJ+bdiIYbNSZH0tTXFeRhp1LxqVw1TkUyXATd6VMnRsoQ3kMA6z+COhyDtNqMgyQFUvCi5GlUnueW3PnuBxIJFpR0JOkg161VXMrfbk7NTtjgbhBWiJGaN1naL1u6Ii54YBYw8XxRHcA2RQ0djXVRR+gALLivHWiMaxgHSnrawOzHNZrr/Hi3u1YGYOxlaiR7Ghr/LvZgZtJ4oo9FNCruHrafL31wsJ7o0WiPO/XdzfABpTLpzNxh05RJyhG7KsjFruAlvnIPnppba5nOSn+Hmz80DSg//b4qh/1vGDNla/llYAMNY4HsS5VbytH9hVapRgdLVqtYheQCsvjy3b52/RwgyBRK/9NFVIfkSKkl+1peVHokOAq/XnbBsuowSYoR4xBrxpZkAKK03r4v2oAVpCRFK/cXsbhkaLbwM+A2zMHnJENof9jL4W1SaGrPrmjsd0NVxdj3mFy9J3bl1/BGaLb17DaNt7MXR7ZkuvtCDx3kgPxTKvyaGd/i6/RSVzd1q3N5g0lqjk8DzH9jL5X4xI63Wf3xi8nIhz6D1cbXytBfvYwFYdr+YDitx+PBr1oxdD7UQqftahuJ7vzMGJ8nAj0rhcD4v+keQBVB+SdxEYyTrC9SdldN0vs/rM+CEX0DwwzSTBkNmure0XAX5aubaBz1ghA1XJZ6zPK9V08IKHXbd2K/jpWjthPnQVLT6mrjjFo8gYK0TaENLjJ0HuLjdPY5DHI1Hh1cLRUOKwy/p6SuZ/GvEj/ErzyVm6jgCW2vnUjyP+xLjk9KV0q8/V8kWa/fxJgVnBFtKSC1KYml90w0ICsFa+9LTa3C0gsI0fn6G5oplKD/11QKt3nvjqP3uMF0knnt+EroJ0Tt/a0h9ilTvdtIb6czOQHkrDmze9vKUw18+h1ioH3ZI+yfSNIrQaCVAlZ5IXjBci5hXsEkPUGsViLTJlDziObwG4CRBeO1cZK5j7vI2Ho2gE+0b735dT5dYhQwZYZhrCuocLaE+YClYLqTSu6J6dJwZb2llJdbBixdzz1KW/V8NArCkrn7PwrYE0Sn31pOQXQRbbjaAYY9EAZ70Eacnx7kJ4E1D48x18yG+oBa4mB2bsH2Fy4WD32+meK0ItLS2w9S8dnOOSbyqLaNRn0+bekr0C2c0/0jjR4nTfkXBhXY1ndLldGK2PkDZwtUkFNwqDj7wvIC6/z9FQLRPmxdai7cb+cMfdr9fp+0gmvwo2if+9Iz67YHORFtemrb8UmuM/vyX4/CulL/DuVeJmD9Kb0/sh7QinbQloFnL82pHg18kY="
}
            fix = requests.post("https://mssdk-i18n.tiktok.com/mssdk/web_common", headers=H3, data=json.dumps(D3))
            ms = fix.cookies.get('msToken')
            url = f"https://www.tiktok.com/passport/web/user/check_email_registered?shark_extra=%7B%22aid%22%3A1459%2C%22app_name%22%3A%22Tik_Tok_Login%22%2C%22app_language%22%3A%22en%22%2C%22device_platform%22%3A%22web_mobile%22%2C%22region%22%3A%22SA%22%2C%22os%22%3A%22ios%22%2C%22referer%22%3A%22https%3A%2F%2Fwww.tiktok.com%2Fprofile%22%2C%22root_referer%22%3A%22https%3A%2F%2Fwww.google.com%22%2C%22cookie_enabled%22%3Atrue%2C%22screen_width%22%3A390%2C%22screen_height%22%3A844%2C%22browser_language%22%3A%22en-us%22%2C%22browser_platform%22%3A%22iPhone%22%2C%22browser_name%22%3A%22Mozilla%22%2C%22browser_version%22%3A%225.0%20%28iPhone%3B%20CPU%20iPhone%20OS%2014_4%20like%20Mac%20OS%20X%29%20AppleWebKit%2F605.1.15%20%28KHTML%2C%20like%20Gecko%29%20Version%2F14.0.3%20Mobile%2F15E148%20Safari%2F604.1%22%2C%22browser_online%22%3Atrue%2C%22timezone_name%22%3A%22Asia%2FRiyadh%22%2C%22is_page_visible%22%3Atrue%2C%22focus_state%22%3Atrue%2C%22is_fullscreen%22%3Afalse%2C%22history_len%22%3A17%2C%22battery_info%22%3A%7B%7D%7D&msToken={ms}&X-Bogus=DFSzsIVLC8A-dJf6SXgssmuyRsO1&_signature=_02B4Z6wo00001dTdX3QAAIDBDn9.7WbolA3U3FvAABfU8c"
            data = f"email={email}&aid=1459&language=en&account_sdk_source=web&region=SA"
            headers = {
                "User-Agent": generate_user_agent(),
                'X-Ladon': ladon,
               'X-Khronos': khrono,
               'X-Argus': argus,
               'X-Gorgon': gorgon
            }
            response = requests.post(url, headers=headers, data=data)
            print(response.text)
            if '"data":{"is_registered":1},"message":"success"' in response.text:
                return {'status': 'ok', 'Available': 'true'}
            elif '{"data":{"is_registered":0},"message":"success"}' in response.text:
            	return {'status': 'ok', 'Available': 'false'}
            else:
                return {'status': 'bad', 'resposne': 'TurnVPN'}
from concurrent.futures import ThreadPoolExecutor
while True:
	with ThreadPoolExecutor(max_workers=5) as executor:
		executor.submit(CheckTik, 'fhdhasd39123@gmail.com')