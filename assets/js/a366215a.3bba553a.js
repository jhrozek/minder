"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[2611],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>y});var n=r(67294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function a(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var s=n.createContext({}),u=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):a(a({},t),e)),r},p=function(e){var t=u(e.components);return n.createElement(s.Provider,{value:t},e.children)},c="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,o=e.originalType,s=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),c=u(r),d=i,y=c["".concat(s,".").concat(d)]||c[d]||f[d]||o;return r?n.createElement(y,a(a({ref:t},p),{},{components:r})):n.createElement(y,a({ref:t},p))}));function y(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=r.length,a=new Array(o);a[0]=d;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[c]="string"==typeof e?e:i,a[1]=l;for(var u=2;u<o;u++)a[u]=r[u];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},24750:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>a,default:()=>f,frontMatter:()=>o,metadata:()=>l,toc:()=>u});var n=r(87462),i=(r(67294),r(3905));const o={title:"Alerts",sidebar_position:60},a="Alerts from Minder",l={unversionedId:"understand/alerts",id:"understand/alerts",title:"Alerts",description:"Alerts are a core feature of Minder providing you with notifications about the status of your registered",source:"@site/docs/understand/alerts.md",sourceDirName:"understand",slug:"/understand/alerts",permalink:"/understand/alerts",draft:!1,tags:[],version:"current",sidebarPosition:60,frontMatter:{title:"Alerts",sidebar_position:60},sidebar:"minder",previous:{title:"Remediations",permalink:"/understand/remediation"},next:{title:"minder",permalink:"/ref/cli/minder"}},s={},u=[{value:"Alert types",id:"alert-types",level:2},{value:"Configuring alerts in profiles",id:"configuring-alerts-in-profiles",level:2}],p={toc:u},c="wrapper";function f(e){let{components:t,...r}=e;return(0,i.kt)(c,(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"alerts-from-minder"},"Alerts from Minder"),(0,i.kt)("p",null,"Alerts are a core feature of Minder providing you with notifications about the status of your registered\nrepositories. These alerts automatically open and close based on the evaluation of the rules defined in your profiles."),(0,i.kt)("p",null,"When a rule fails, Minder opens an alert to bring your attention to the non-compliance issue. Conversely, when the\nrule evaluation passes, Minder will automatically close any previously opened alerts related to that rule."),(0,i.kt)("p",null,"In the alert, you'll be able to see details such as:"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"The repository that is affected"),(0,i.kt)("li",{parentName:"ul"},"The rule type that failed"),(0,i.kt)("li",{parentName:"ul"},"The profile that the rule belongs to"),(0,i.kt)("li",{parentName:"ul"},"Guidance on how to remediate and also fix the issue"),(0,i.kt)("li",{parentName:"ul"},"Severity of the issue. The severity of the alert is based on what is set in the rule type definition.")),(0,i.kt)("h2",{id:"alert-types"},"Alert types"),(0,i.kt)("p",null,"Minder supports alerts of type GitHub Security Advisory."),(0,i.kt)("p",null,"The following is an example of how the alert definition looks like for a give rule type:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: rule-type\nname: artifact_signature\n...\ndef:\n  # Defines the configuration for alerting on the rule\n  alert:\n    type: security_advisory\n    security_advisory:\n      severity: "medium"\n')),(0,i.kt)("h2",{id:"configuring-alerts-in-profiles"},"Configuring alerts in profiles"),(0,i.kt)("p",null,"Alerts are configured in the ",(0,i.kt)("inlineCode",{parentName:"p"},"alert")," section of the profile yaml file. The following example shows how to configure\nalerts for a profile:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'```yaml\n---\nversion: v1\ntype: profile\nname: github-profile\ncontext:\n  provider: github\nalert: "on"\nrepository:\n  - type: secret_scanning\n    def:\n      enabled: true\n```\n')),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"alert")," section can be configured with the following values: ",(0,i.kt)("inlineCode",{parentName:"p"},"on"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"off")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"dry_run"),". The default value is ",(0,i.kt)("inlineCode",{parentName:"p"},"on"),"."))}f.isMDXComponent=!0}}]);