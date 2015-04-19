/**
 * JSA Report Module <report.js>
 * 
 * @copyright   Team JSA 
 * @author      kartell
 * @package     JSA
 * @date        12.2013
 */

function Reporter(){
	if ( arguments.callee._singletonInstance ){
		return arguments.callee._singletonInstance;
	}
	arguments.callee._singletonInstance = this;
	
	var reports = new Array();
	
	this.add_report = function(directive, policy, object){
		var content = "";
		// Clone Node and remove JSA attributes for clean reporting
		var obj = object.cloneNode(true);
		
		while (obj.getAttribute(JSA._random) != null){
			obj.removeAttribute(JSA._random);
		}
		
		while (obj.getAttribute(JSA._random+"access") != null){
			obj.removeAttribute(JSA._random+"access");
		}	
		
		if (obj.nodeName.toLowerCase() === 'script'){
			content = obj.outerHTML;
			if (!content){
				content = obj.textContent;
				if (config.verbose){ JSA.info("[report] script without outerHTML"); }				
			}
			if (config.verbose){ JSA.info("[report] script"); }		
		}
		else if(obj.nodeName.toLowerCase() === 'iframe'){
			content = obj.outerHTML;
			if (config.verbose){ JSA.info("[report] iframe"); }		
		}
		else if(obj.nodeName.toLowerCase() === 'input'){
			content = obj.outerHTML;
			if (config.verbose){ JSA.info("[report] input"); }		
		}
		else if(obj.nodeName.toLowerCase() === 'applet'){
			content = obj.outerHTML;
			if(config.verbose){ JSA.info("[report] applet"); }
		}
		else if(obj.nodeName.toLowerCase() === 'svg'){
			content = "TBD";
			if (config.verbose){ JSA.info("[report] svg"); }		
		}
		else{
			content ="unknown";
			if (config.verbose){ JSA.info("[report] unknown obj"); }		
		}
			
		var report = {
			'directive': directive,
			'rule': policy,
			'obj': content
			};
		
		reports.push(report);
	}

	this.send_report = function(){		
		//send via XHR
		function sendXHR(report){
			var xhr = new XMLHttpRequest();
					
			xhr.open("POST", config.jsagency_xhr_url, true);
			xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
			xhr.send('report='+report);
			JSA.info("XHR report send: "+report);
		}
		
		//send via WebSockets
		function sendWS(report){
			try {
				var ws = new WebSocket(xonfig.jsagency_ws_url);			
				ws.onopen = function(){
					ws.send(report);
				}
					
				ws.onmessage = function(evt){
					JSA.info("WebSocket msg received: "+evt.data);
				}
				
				ws.onerror = function(evt){
					JSA.info("WebSocket error: Switching to XHR report. "+evt.data);
					//ws.close();
					sendXHR(report);
				}
				
				ws.onclose = function(){
					JSA.info("WebSocket Closed.");
				}
				
			} catch (e){
				//Is not triggerd if server is unavailable -> ws.onerror
				JSA.info("WS Service unavailable. Switching to XHR report: "+e);
				sendXHR(report);
			}			
		}			
		
		
		//~ //build JSON report
		var report = JSON.stringify({
			'url': window.location.href,
			'referrer': document.referrer,
			'reports': reports
		});
		
		// encode report
		report = encodeURIComponent(window.btoa(report));
		
		//send report according to config, use XHR as fallback
		if (config.xhr_only == true){
			sendXHR(report);
		}
		else{
			/*	Report as WebSocket	*/
			if (window.WebSocket){
				sendWS(report);
			}
			/*	Report as XHR	*/
			else {
				sendXHR(report);
			}
		}
		
		//reset report array, after send
		this.reports = new Array();
	}
}

//init reporter
JSA.reporter = new Reporter();