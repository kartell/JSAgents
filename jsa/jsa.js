/**
 * JSA Core Library <jsa.js>
 * 
 * @copyright   RUB/NDS/Team JSA 
 * @author      .mario
 * @package     JSA
 * @date        12.2013
 */

!function () {


    /**
     * Configuration data
     */
    var config = {
        verbose: true,
        policy_type: 0,     // 0: protect, 1: report only 
        protect: true,      // remove DOM nodes on policy violation
        report: true,      // send report on policy violation
        xhr_only: true,  // false: try WebSocket, use xhr as fallback, true: only use xhr for reporting 
        jsagency_xhr_url: "http://192.168.56.101/JSA/int/report/", // XHR Destination to send report to
        jsagency_ws_url: "ws://192.168.56.101:8888/jsa" // WebSocket Destination to send report to
    };
        
    /**
     * Tidy up the scope, declare JSA core object
     */
    
    var JSA = this;
    
    
    /**
     * Init method <init ()>
     * 
     * This method is being called before any other method
     * 
     * @param     void
     * @return    boolean call state
     */
    
    this.init = function () {
        
        // say hello nicely
        JSA.info('Says hello at ' + Date.now())
        
        // determine path dynamically
        var scripts = document.getElementsByTagName("script");
        var path    = scripts[scripts.length-1].src.slice(0,-6);
        
        // load modules and policies
	// directory structure needed, as it is in repository
        JSA.module(path + 'modules/enforcer', true);
        JSA.module(path + 'modules/md5', true);
        JSA.module(path + 'modules/report', true);        
        JSA.policy(path + 'policies/xss', true);
    
        // freeze the document
        JSA.freeze(document);        
        
        // define policy timeout
        JSA.policy_timeout = setTimeout(function () {
           
            // block document access, close document
            document.write('ERROR: Policy files could not be loaded');
            document.close();
            JSA.warn("Policy could not be loaded for this site.");
        }, 2500);

        // check async policy load
        JSA.si = setInterval (function () {
            if(JSA._policies.length === JSA._policy_count 
                && JSA._modules === JSA._module_count){
                
                // pre-conditions met, clear timeouts, interval
                clearTimeout (JSA.policy_timeout);
                clearInterval(JSA.si);
                
                // create JSA document to check on
                JSA.doc = JSA.create();
                            
                // pre-filter markup for multiple body elements
                var markup = document.getElementById(JSA._random).textContent;
                markup = markup.replace(/(.)<body/gim, '$1<div');
                            
                //@TODO try to find a way to make it nicer!
                JSA.doc.documentElement.innerHTML = '<html><head>' 
                    + markup;
                    
                        // iterate over policies, extract selector, enforce
                        for(var index in JSA._policies) {
                            var policy = JSA._policies[index][1];
                            for(var selector in policy){
                                if(selector && policy[selector]){
                                    JSA.enforce(selector, policy[selector])
                                }
                            }
                        }
                        
                //Send policy violations
                if (config.report === true){
                    JSA.reporter.send_report();
                }
                
                // done with the policies, now filter
                JSA.filter();
                                
                // render the sanitized document
                JSA.render();
            }
                
        }, 0);
        JSA.log('Finished initializing');
        return true;
    }


    /**
     * Info handler <info()>
     * 
     * @param    info string
     * @return   void 
     */
    
    this.info = this.log = function (s) {
        console.info('JSA: ' + s);
    }

    /**
     * Warning handler <warning()>
     * 
     * @param    warning string
     * @return   void 
     */
    
    this.warn = function (s) {
        console.warn('JSA: ' + s);
    }
    
    
    /**
     * Error handler <error()>
     * 
     * @param    object error object
     * @return   void 
     */
    
    this.err = function (e) {
        console.error('JSA: ' + e);
    }    
    
    
    /**
     * Load method <module()>
     * 
     * This method fetches and executes other JSA resources
     * 
     * @param     string     url    module to fetch
     * 
     * @return     mixed    exec state
     */
    
    this.module = function (url) {
        
        // update required module count
        JSA._module_count+=1;
        var x = new XMLHttpRequest;
        x.open('GET', url + '.js');

        // module found, evaluate code
        x.onload = function () {
            var rt = x.responseText;
            try {
                eval(rt); 
                return JSA._modules++;
            } catch(e) {
                JSA.err(e);
            }
        }
        x.send(null);
    }
    
    
    /**
     * Load policy <this.policy()>
     * 
     * This method fetches and parses policies
     * 
     * @param     string     url    policy to fetch
     * 
     * @return     object    policy literal
     */
    
    this.policy = function (url, type) {
        
        // update required policy count
        JSA._policy_count+=1;
        //var data = new FormData();
        //data.append('url', document.location.href);
        //data.append('policy_type', type);        
        
        var x = new XMLHttpRequest;
        x.open('GET', url);
        
        // policy found, parse
        x.onload = function () {
            console.log("Policy loaded: "+url+" ("+Date.now()+")");
            var rt = x.responseText;
            
            // Check for Server error messages        
            if (rt.substring(0,7) == "[error]"){
                JSA.err(rt);
                return;
            }
            
            // No error, keep going
            try {
                JSA._policies.push([url, JSON.parse(rt)]);
            } catch(e) {
                JSA.err(e);
            }
        }
	x.send(null);
        //x.send(data);
    }
    
    
    /**
     * Enforce policy
     * 
     * @return void
     */
    
    this.enforce = function (selector, policy) {
        
        // select matching elements
        var elements = JSA.doc.querySelectorAll(selector);
        
        // check if matching elements were found, enforce policy
        if(!elements.length){
            JSA.warn('No elements selected by selector: ' + selector);
        } else {
            JSA.info('Found ' + elements.length + ' elements for selector: ' 
                + selector);
            
            // now revisit and enforce
            JSA._enforce(elements, policy);
        }
    }    
    
    
    /**
     * Freeze the document <this.freeze()>
     * 
     * @return void
     */
    
    this.freeze = function (doc) {
        
        // seal existing document before freezing
        JSA.seal(doc);
        
        // freeze and blind the whole document
        doc.write('<plaintext id="' + JSA._random 
            + '" style="display:none">');
            
        doc.close();
    }

    /**
     * Seal existing document objects <this.seal()>
     * 
     * @param  document
     * 
     * @return void
     */
    
    this.seal = function (doc) {
        for(var item in doc){
            if(typeof doc[item] === 'function'){
                Object.defineProperty(
                    doc, item, {value: doc[item], configurable:false}
                );
            }
        }
        return doc;
    }


    /**
     * Create new document <this.create()>
     * 
     * @return document
     */
    
    this.create = function () {
        return JSA.seal(document.implementation.createHTMLDocument(''));
    }
    
    
    /**
     * Finalize DOM <this.finalize()>
     * 
     * @param  void
     * 
     * @return void
     */
    
    this.filter = function () {
        
        // remove elements with kill-switch
        var elements = JSA.doc.querySelectorAll('*');
        for(var index in elements){
            if(elements[index].tagName) { 
                if(elements[index].getAttribute(JSA._random) === 'del') { 
                    elements[index].parentNode.removeChild(elements[index])
                }
            }
        }
    }    
    
    /**
     * Render new document
     * 
     * @return void
     */
    
    this.render = function () {
        
        // apply corrected markup
        document.documentElement.innerHTML 
            = JSA.doc.documentElement.innerHTML;
            
        // freeze flagged elements
        var freeze = document.querySelectorAll('*['+_random+'freeze]')
        for(var elm in freeze) {
            if(freeze[elm].tagName) {
                var observer = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        alert('form tamper detected');
                    });   
                });
                var config = {
                    attributes: true, 
                    childList: true, 
                    characterData: true
                };
                observer.observe(freeze[elm], config);
                Object.defineProperty(freeze[elm], 'value', {set: function(){
                    return alert('form value tamper detected');
                }});
            }
        }
        
        // forbid access to protected elements
        var access = document.querySelectorAll('*['+_random+'access]')
        for(var elm in access) {
            if(access[elm].tagName) {
                for(var i in access[elm]){
                    // null all properties of the protected element
                    try {
                        Object.defineProperty(access[elm], i, {value: null});
                    } catch(e) {}
                }
            }
        }     
        
        // re-activate legitimate scripts
        var scripts = document.querySelectorAll('script');
        for(var i in scripts){
            if(scripts[i].tagName) {
                if(scripts[i].src) {
                    var script = document.createElement('script')
                    script.src = scripts[i].src + '#';
                    document.body.appendChild(script);
                } else {
                    try {
                        eval(scripts[i].textContent)
                    } catch(e) {}
                }
            }
        }
        document.close();
    }


    /**
     * Internal data
     */
    
    this._policies = [];
    this._modules  = 0;
    
    this._policy_count = 0;
    this._module_count = 0;
    
    this._random = 'jsa-' + Math.random().toString(36).replace(/\./, '');
    
    
    /**
     * Start JSA
     */
    
    init();
    
}()/** and here be dragons */
