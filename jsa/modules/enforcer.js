/**
 * JSA Enforcer Module <enforcer.js>
 * 
 * @copyright   RUB/NDS/Team JSA 
 * @author      .mario
 * @package     JSA
 * @date        12.2013
 */

JSA._enforce = function(elements, policy){
    
    /**
     * Init rule enforcement
     * 
     * @param  void
     * 
     * @return void
     */
    
    this._enforce_init = function () {
        
        // Iterate over existing policies    
        for(var directive in policy){
            switch(directive) {
                
                // XSS directives                    
                case 'iframe-elements' :
                case 'object-elements' :
                case 'embed-elements' :
                case 'applet-elements' :
                case 'script-elements' :
                case 'svg-elements' :
                
                    JSA.xss_element_enforcer(elements, directive, policy);
                    break;
                
                case 'javascript-uris' :
                case 'data-uris' :
                case 'event-handlers' :   
                case 'form-access' :
                case 'link-access' :
                
                    JSA.xss_attribute_enforcer(elements, directive, policy);
                    break;
                    
                case 'freeze' :
                case 'access' :
                
                    JSA.freeze_enforcer(elements, directive, policy);
                    break;                    
                
                // Sidechannel directives
                // @TODO
            }
        }
    }
    
    /**
     * Private method to enforce element 
     * existence or src rules
     * 
     * @return void
     */
    
    this.xss_element_enforcer = function(elements, directive, policy){
        
        var tagname  = directive.match(/^\w+/)[0];
        var elements = JSA.xss_get_elements(elements, true); 
        if(elements.length){
            for(var index in elements){
                
                // iterate over in-scope html elements
                if(elements[index].tagName 
                        && tagname === elements[index].tagName.toLowerCase()) {
                    if(!policy[directive]){
                        
                        // #report#
                        if (config.report === true){
                            JSA.reporter.add_report(directive, 
                                policy[directive],elements[index]);
                        }
                        if (config.protect === true){
                            elements[index].setAttribute(JSA._random, 'del');
                        }
                        
                    } else if(policy[directive] === 'same-domain') {
                        var src = JSA.xss_extract_source(elements[index], 'src');
                        
                        //hack to get only the first string from object (array)
                        src = src[0];
                        if(src && typeof src === 'string'){
                            
                            // detect same-domain source on IE,FF,O,GC,Sf
                            if(!src.match(/\/\/|:/) 
                                || src.match(new RegExp('^' 
                                 + location.protocol + '//'  
                                 + location.host + '/'))){
                                elements[index].setAttribute(
                                    JSA._random, 'add');
                            } else {
                                // #report#
                                if (config.report === true){
                                    JSA.reporter.add_report(directive, 
                                        policy[directive],elements[index]);
                                }
                                if (config.protect === true){
                                    elements[index].setAttribute(
                                        JSA._random, 'del');
                                }
                            }
                        } else {
                            // #report#
                            if (config.report === true){
                                JSA.reporter.add_report(directive, policy[directive],elements[index]);
                            }
                            if (config.protect === true){
                                elements[index].setAttribute(JSA._random, 'del');
                            }
                        }
                    } else {
                        elements[index].setAttribute(JSA._random, 'add');
                    }
                } 
            }
        }
    }
    
    /**
     * Private method to enforce attribute filters
     * 
     * @return void
     */
    
    this.xss_attribute_enforcer = function (elements, directive, policy) {

        var elements = JSA.xss_get_elements(elements, false); 
        if(elements.length){
            for(var index in elements){
                
                // iterate over in-scope html elements
                if(elements[index].tagName) { 
                    if(!policy[directive]){
                        var src = JSA.xss_extract_source(elements[index]);
                        for(var i in src){
                            // check for data URIs
                            if(directive === 'data-uris') {
                                if(src[i].match(/^data:/i)){
                                    // #report#
                                    if (config.report === true){
                                        JSA.reporter.add_report(directive, 
                                            policy[directive],elements[index]);
                                    }
                                    if (config.protect === true){
                                        elements[index].setAttribute(
                                            JSA._random, 'del');    
                                    }
                                }
                                
                            // check for javascript/vbscript URIs
                            } else if(directive === 'javascript-uris') {
                                if(src[i].match(/^\w+script:/)){
                                    // #report#
                                    if (config.report === true){
                                        JSA.reporter.add_report(directive, 
                                            policy[directive],elements[index]);
                                    }
                                    if (config.protect === true){
                                        elements[index].setAttribute(
                                            JSA._random, 'del');
                                    }
                                }
                            }
                        }
                        
                        // now check for event handlers
                        for(var i in elements[index].attributes){
                            if(elements[index].attributes[i]){
                                var name = elements[index].attributes[i].name;
                                if(typeof name === 'string' && name.match(/^on/i)){
                                    // #report#
                                    if (config.report === true){
                                        JSA.reporter.add_report(directive, 
                                            policy[directive],elements[index]);
                                    }
                                    if (config.protect === true){
                                        elements[index].setAttribute(
                                            JSA._random, 'del');
                                    }
                                }
                            }
                        }
                        
                        // finally check for malicious styles (Opera only)
                        if(typeof opera == 'object') {
                            for(var i in elements[index].style){
                                if(elements[index].style[i]){
                                    var value = elements[index].style[i];
                                    if(value && typeof value === 'string'){
                                        if(value.match(/data:|\w+script:/i)){
                                            // #report#
                                            if (config.report === true){
                                                JSA.reporter.add_report(
                                                    directive, policy[directive], 
                                                    elements[index]);
                                            }
                                            if (config.protect === true){
                                                elements[index].setAttribute(
                                                    JSA._random, 'del');
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                    } else {
                        elements[index].setAttribute(JSA._random, 'add');
                    }
                }
            }
        }
        
    }
    
    /**
     * Private method to enforce element freezing
     * 
     * @return void
     */
    
    this.freeze_enforcer = function(elements, directive, policy){
        
        var elements = JSA.xss_get_elements(elements, true); 
        if(elements.length){
            for(var index in elements){
                // iterate over in-scope html elements
                if(elements[index].tagName) {
                    // mark elements as to be frozen
                    if(policy.freeze === true){
                        elements[index].setAttribute(JSA._random + 'freeze', '');
                    }
                    // set access property
                    if(policy.access === false){
                        elements[index].setAttribute(JSA._random + 'access', '');
                    }
                } 
            }
        }
    }    
    
    /**
     * Return an array of src values;
     * We use an array to avoid src spoofing attacks
     * 
     * @param  object element
     * 
     * @return array  sources 
     */
    this.xss_extract_source = function(element, attribute_type){
        // By default get all attribute types
        var attribute_type = attribute_type || '*';
        // define sources array and retrieve data
        var sources = [];
        for(var i in element.attributes){
            if(element.attributes[i].name 
                && element.attributes[i].value
                && typeof element.attributes[i].name  === 'string'
                && typeof element.attributes[i].value === 'string'){
                    if (element.attributes[i].name  === attribute_type 
                        || attribute_type === '*'){
                        sources.push(element.attributes[i].value);
                    }
            }
        }
        return sources;        
    }

    /**
     * Call this method to get all elements on the page
     * 
     * @return object elements
     */
    
    this.xss_get_elements = function(elements, recursive){
        
        // recursion only for element based XSS rules
        if(recursive 
            && JSA.doc.querySelectorAll('*').length !== elements.length){
            
            // we have a non-star selector requiring re-selection
            var all = [];
            for(index in elements){
                if(elements[index].tagName){
                    var children = elements[index].querySelectorAll('*');
                    all.push(elements[index]);
                    for(var index2 in children) {
                        if(children[index2].tagName) {
                            all.push(children[index2]);
                        }
                    }
                }
            }
            elements = all;
        }        
        return elements;
    }
    
    // start enforcing DOM policies
    JSA._enforce_init();    
};

