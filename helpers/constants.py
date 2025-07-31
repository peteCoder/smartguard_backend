# Optional suspicious TLD flag
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", # Free domains (very common in scams)
    "xyz", "top", "buzz", "info", "win", # Cheap or spammy
    "club", "vip", "loan", "click", "work",
    "support", "review", "fit", "country", "space",
    "trade", "download", "science", "party", "cam",
    "stream", "men", "racing", "mom", "gdn",
    "accountants", "faith", "date", "cricket", "science"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin", "signup",
    "validate", "password", "auth", "authentication", "reset", "support", "service",
    "banking", "alert", "access", "invoice", "payment", "refund", "billing", "admin",
    "webmail", "unlock", "important", "helpdesk", "security", "credentials", "token"
]

BRAND_TARGETS = [
    "paypal", "venmo", "zelle", "cashapp", "stripe", "chime", "revolut", "monzo", "wise", "jpmorgan",
    "citibank", "chase", "bankofamerica", "boa", "wellsfargo", "barclays", 
    "hsbc", "capitalone", "fidelity", "robinhood", "amazon", "ebay", "aliexpress", 
    "walmart", "flipkart", "shein", "etsy", "target", "bestbuy",
    "google", "gmail", "outlook", "hotmail", "yahoo", "protonmail", "zoho", "office3653", "microsoft", "icloud",
    "facebook", "fb", "instagram", "insta", "meta", "twitter", "x", "tiktok", "snapchat", "discord", "linkedin", 
    "reddit", "whatsapp", "telegram",
    "github", "gitlab", "bitbucket", "slack", "zoom", "dropbox", "figma", "notion", "asana", "jira", "confluence",
    "steam", "epicgames", "roblox", "fortnite", "xbox", "playstation", "nintendo", "twitch",
    "netflix", "hulu", "disney", "primevideo", "spotify", "verizon", "att", "tmobile", "comcast",
    "1password", "lastpass", "authy", "okta", "duo", "norton", "mcafee"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "adf.ly", "shorte.st", "cutt.ly", "v.gd", "tr.im", "cli.gs", "bl.ink", "tiny.cc",
    "soo.gd", "qr.ae", "chilp.it", "x.co", "yourls.org", "u.to", "lnkd.in", "rb.gy",
    "short.io", "short.cm", "1url.com", "linktr.ee", "s.id", "hyperurl.co", "gg.gg"
]

BRAND_TRUSTED_TLDS = {
    "paypal": {"com"},
    "microsoft": {"com", "net"},
    "chase": {"com"},
    "bankofamerica": {"com"},
    "wellsfargo": {"com"},
    "citibank": {"com"},
    "boa": {"com"},
    "jpmorgan": {"com"},
    "capitalone": {"com"},
    "fidelity": {"com"},
    "robinhood": {"com"},

    "facebook": {"com"},
    "fb": {"com"},
    "instagram": {"com"},
    "meta": {"com"},
    "twitter": {"com"},
    "x": {"com"},
    "tiktok": {"com"},
    "snapchat": {"com"},
    "discord": {"com"},
    "linkedin": {"com"},
    "reddit": {"com"},
    "whatsapp": {"com"},
    "telegram": {"org"},

    "google": {"com"},
    "gmail": {"com"},
    "youtube": {"com"},
    "android": {"com"},
    "chrome": {"com"},
    "googleads": {"com"},
    "gstatic": {"com"},

    "amazon": {"com"},
    "primevideo": {"com"},
    "aliexpress": {"com"},
    "walmart": {"com"},
    "flipkart": {"com"},
    "shein": {"com"},
    "etsy": {"com"},
    "target": {"com"},
    "bestbuy": {"com"},

    "apple": {"com"},
    "icloud": {"com"},
    "itunes": {"com"},

    "hotmail": {"com"},
    "outlook": {"com"},
    "office365": {"com"},
    "protonmail": {"com"},
    "zoho": {"com"},
    "yahoo": {"com"},

    "netflix": {"com"},
    "hulu": {"com"},
    "disney": {"com"},
    "spotify": {"com"},

    "github": {"com"},
    "gitlab": {"com"},
    "bitbucket": {"org"},
    "slack": {"com"},
    "zoom": {"us"},
    "notion": {"so"},
    "figma": {"com"},
    "asana": {"com"},
    "jira": {"com"},
    "confluence": {"com"},

    "steam": {"com"},
    "epicgames": {"com"},
    "roblox": {"com"},
    "fortnite": {"com"},
    "xbox": {"com"},
    "playstation": {"com"},
    "nintendo": {"com"},
    "twitch": {"tv"},

    "1password": {"com"},
    "lastpass": {"com"},
    "authy": {"com"},
    "okta": {"com"},
    "duo": {"com"},
    "norton": {"com"},
    "mcafee": {"com"},

    "verizon": {"com"},
    "att": {"com"},
    "tmobile": {"com"},
    "comcast": {"com"},
}



