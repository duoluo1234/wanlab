#!/usr/bin/env python3
"""给 wanlab 的端点目录补中文备注（vendor_cn / city_cn / country_cn / continent_cn / kind_cn）。
   目录本身来自 m2c.1ms.dog；未收录的条目会打印出来（刷新目录后跑一次就知道要补哪些）。"""
import json, os, sys

CITY = {
    "Singapore": "新加坡", "Frankfurt": "法兰克福", "São Paulo": "圣保罗", "London": "伦敦",
    "Tokyo": "东京", "Madrid": "马德里", "Hong Kong": "香港", "Sydney": "悉尼", "Jakarta": "雅加达",
    "Paris": "巴黎", "Milan": "米兰", "Seoul": "首尔", "Osaka": "大阪", "Toronto": "多伦多",
    "Amsterdam": "阿姆斯特丹", "Stockholm": "斯德哥尔摩", "Melbourne": "墨尔本", "Beijing": "北京",
    "Johannesburg": "约翰内斯堡", "Guangzhou": "广州", "Virginia": "弗吉尼亚", "Zurich": "苏黎世",
    "Mumbai": "孟买", "Kuala Lumpur": "吉隆坡", "Bangkok": "曼谷", "Dallas": "达拉斯",
    "Silicon Valley": "硅谷", "Warsaw": "华沙", "Querétaro": "克雷塔罗", "Dublin": "都柏林",
    "Tel Aviv": "特拉维夫", "Chicago": "芝加哥", "Riyadh": "利雅得", "Dubai": "迪拜",
    "Atlanta": "亚特兰大", "Los Angeles": "洛杉矶", "Santiago": "圣地亚哥", "Shanghai": "上海",
    "Washington": "华盛顿", "Oregon": "俄勒冈", "Montreal": "蒙特利尔", "Montréal": "蒙特利尔",
    "Hyderabad": "海得拉巴", "Auckland": "奥克兰", "Cardiff": "加的夫", "Ashburn": "阿什本",
    "Phoenix": "凤凰城", "Chuncheon": "春川", "Salt Lake City": "盐湖城", "Delhi": "德里",
    "Bangalore": "班加罗尔", "Mexico City": "墨西哥城", "Miami": "迈阿密", "Seattle": "西雅图",
    "Nanjing": "南京", "Wuhan": "武汉", "Qingdao": "青岛", "Ulanqab": "乌兰察布",
    "Chengdu": "成都", "Manila": "马尼拉", "Iowa": "爱荷华", "Chennai": "金奈", "Doha": "多哈",
    "San Francisco": "旧金山", "Hillsboro": "希尔斯伯勒", "N. Virginia": "弗吉尼亚北部",
    "Ohio": "俄亥俄", "N. California": "北加州", "Calgary": "卡尔加里", "UAE": "阿联酋",
    "Cape Town": "开普敦", "Taipei": "台北", "Ningxia": "宁夏", "Monterrey": "蒙特雷",
    "Abu Dhabi": "阿布扎比", "Casablanca": "卡萨布兰卡", "San Jose": "圣何塞", "Jeddah": "吉达",
    "Marseille": "马赛", "Jerusalem": "耶路撒冷", "Batam": "巴淡岛", "Vinhedo": "维涅杜",
    "Valparaiso": "瓦尔帕莱索", "San Antonio": "圣安东尼奥", "Bogota": "波哥大", "Lenexa": "莱内克萨",
    "Des Moines": "得梅因", "Abilene": "阿比林", "Kulai": "古来", "Shawnee": "肖尼",
    "Boardman": "博德曼", "Quincy": "昆西", "Rio de Janeiro": "里约热内卢", "Delhi NCR": "德里首都圈",
    "New Jersey": "新泽西", "Honolulu": "檀香山", "Manchester": "曼彻斯特", "Hangzhou": "杭州",
    "Fuzhou": "福州", "Zhangjiakou": "张家口", "Hohhot": "呼和浩特", "Shenzhen": "深圳",
    "Heyuan": "河源", "Chongqing": "重庆", "Beijing 1": "北京①", "Beijing 4": "北京④",
    "Shanghai 1": "上海①", "Shanghai 2": "上海②", "Guangzhou-Friendly": "广州(专线)",
    "Guiyang": "贵阳", "Cairo": "开罗", "Mexico City 1": "墨西哥城①", "Mexico City 2": "墨西哥城②",
    "Istanbul": "伊斯坦布尔", "Illinois": "伊利诺伊", "Texas": "德克萨斯", "Wyoming": "怀俄明",
    "California": "加州", "Arizona": "亚利桑那", "Quebec City": "魁北克城", "Geneva": "日内瓦",
    "Oslo": "奥斯陆", "Gävle": "耶夫勒", "Pune": "浦那", "Jamnagar": "贾姆讷格尔",
    "Nagpur": "那格浦尔", "Newark": "纽瓦克", "London 2": "伦敦②", "Mumbai 2": "孟买②",
    "Frankfurt 2": "法兰克福②", "Singapore 2": "新加坡②", "Tokyo 3": "东京③",
    "Washington 2": "华盛顿②", "New York": "纽约", "Richmond": "里士满",
    "Falkenstein": "法尔肯施泰因", "Nuremberg": "纽伦堡", "Helsinki": "赫尔辛基",
    "Gravelines": "格拉沃利讷", "Roubaix": "鲁贝", "Strasbourg": "斯特拉斯堡",
    "Beauharnois": "博阿努瓦", "Vint Hill": "文特希尔", "Oklahoma": "俄克拉荷马",
    "South Carolina": "南卡罗来纳", "Columbus": "哥伦布", "Alabama": "亚拉巴马",
    "Las Vegas": "拉斯维加斯", "Belgium": "比利时", "Netherlands": "荷兰", "Berlin": "柏林",
    "Turin": "都灵", "Finland": "芬兰", "Dammam": "达曼", "Taiwan": "台湾", "Johor": "柔佛",
    "Baoding": "保定", "Suzhou": "苏州", "?": "—", "--": "—",
}

VENDOR = {
    "aws": "AWS", "oracle": "甲骨文云", "vultr": "Vultr", "azure": "微软 Azure",
    "gcp": "谷歌云", "aliyun": "阿里云", "tencent": "腾讯云", "huawei": "华为云",
    "linode": "Akamai(Linode)", "digitalocean": "DigitalOcean", "ovh": "OVHcloud",
    "hetzner": "Hetzner", "ibm": "IBM 云", "scaleway": "Scaleway",
    "volcengine": "火山引擎", "baidu": "百度智能云", "naver": "Naver 云",
    "check": "网络检测",
}

COUNTRY = {
    "AE": "阿联酋", "AU": "澳大利亚", "BE": "比利时", "BR": "巴西", "CA": "加拿大",
    "CH": "瑞士", "CL": "智利", "CN": "中国", "CO": "哥伦比亚", "DE": "德国", "EG": "埃及",
    "ES": "西班牙", "FI": "芬兰", "FR": "法国", "GB": "英国", "HK": "中国香港",
    "ID": "印尼", "IE": "爱尔兰", "IL": "以色列", "IN": "印度", "IT": "意大利",
    "JP": "日本", "KR": "韩国", "MA": "摩洛哥", "MX": "墨西哥", "MY": "马来西亚",
    "NL": "荷兰", "NO": "挪威", "NZ": "新西兰", "PH": "菲律宾", "PL": "波兰",
    "QA": "卡塔尔", "SA": "沙特", "SE": "瑞典", "SG": "新加坡", "TH": "泰国",
    "TR": "土耳其", "TW": "中国台湾", "US": "美国", "ZA": "南非", "VI": "美属维尔京",
    "--": "—",
}

# ★ 目录里用的是 "as"（Asia）不是 "ap"，另有 "xx" 表示未知 —— 都得映射
CONTINENT = {"na": "北美", "sa": "南美", "eu": "欧洲", "as": "亚太", "ap": "亚太",
             "me": "中东", "af": "非洲", "oc": "大洋洲", "xx": "—", "": ""}

# 目录里国内/东亚厂商常常没有 continent 字段，按国家补一次，别让表里出现一堆「—」
COUNTRY_CONT = {
    "CN": "ap", "HK": "ap", "TW": "ap", "JP": "ap", "KR": "ap", "SG": "ap", "MY": "ap",
    "TH": "ap", "ID": "ap", "PH": "ap", "IN": "ap", "NZ": "ap", "AU": "ap",
    "US": "na", "CA": "na", "MX": "na", "VI": "na",
    "BR": "sa", "CL": "sa", "CO": "sa",
    "GB": "eu", "DE": "eu", "NL": "eu", "BE": "eu", "FR": "eu", "IT": "eu", "ES": "eu",
    "CH": "eu", "SE": "eu", "NO": "eu", "FI": "eu", "PL": "eu", "IE": "eu", "TR": "eu",
    "AE": "me", "SA": "me", "QA": "me", "IL": "me", "EG": "af", "MA": "af", "ZA": "af",
}

KIND = {
    "DynamoDB /ping": "DynamoDB 探活", "Object Storage": "对象存储",
    "Looking glass": "测速回显", "Cognitive Services": "认知服务",
    "Storage regional endpoint (rep)": "存储区域端点",
    "OSS": "对象存储", "COS": "对象存储", "OBS": "对象存储", "Spaces": "对象存储",
    "Speed test (proof)": "测速点", "Cloud Object Storage": "云对象存储",
    "TOS": "对象存储", "BOS": "对象存储", "检查点": "检查点",
}


def main(path):
    d = json.load(open(path, encoding="utf-8"))
    miss_city, miss_vendor, miss_country = set(), set(), set()
    for e in d["endpoints"]:
        v = e["vendor"]
        e["vendor_cn"] = VENDOR.get(v) or (miss_vendor.add(v) or e.get("vendor_name") or v)
        c = e.get("city") or ""
        if not c:
            e["city_cn"] = "—"
        else:
            e["city_cn"] = CITY.get(c) or (miss_city.add(c) or c)
        cc = e.get("country") or ""
        if not cc or cc == "--":
            e["country_cn"] = "—"
        else:
            e["country_cn"] = COUNTRY.get(cc) or (miss_country.add(cc) or cc)
        cont = e.get("continent") or COUNTRY_CONT.get(cc, "")
        e["continent_cn"] = CONTINENT.get(cont) or "—"
    # 厂商级中文名也写进 vendors 表（前端首屏勾选直接用）
    for k, meta in d["vendors"].items():
        meta["name_cn"] = VENDOR.get(k, meta.get("name", k))
        kind = meta.get("kind") or ""
        meta["kind_cn"] = KIND.get(kind, kind)
    json.dump(d, open(path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print("端点:", len(d["endpoints"]), "→ 已补中文")
    for label, s in (("城市", miss_city), ("厂商", miss_vendor), ("国家", miss_country)):
        if s:
            print(f"!! 未收录的{label}（需补表）:", sorted(s))
    if not (miss_city or miss_vendor or miss_country):
        print("对照表覆盖完整，无遗漏。")
    return 0


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "endpoints.json")
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else default))
