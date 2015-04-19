{
    "*" : {
        "cookie-access"     : false, 
        
        "iframe-elements"   : false,
        "object-elements"   : false,
        "embed-elements"    : false,
        "applet-elements"   : false,
        "svg-elements"      : true,
        "script-elements"   : "same-domain",
        
        "javascript-uris"   : false,
        "data-uris"         : false,
        "event-handlers"    : false
    },
    "body" : {
        "event-handlers"    : true
    },
    "div.evil" : {
        "applet-elements"   : true,
        "script-elements"   : true
    },
    "div#evil" : {
        "iframe-elements"   : false,
        "script-elements"   : false
    },
    "form, input, select, option, textarea" : {
        "freeze"            : true,
        "access"            : false
    }
}