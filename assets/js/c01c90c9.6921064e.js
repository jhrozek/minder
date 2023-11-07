"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[9337],{3905:(e,r,t)=>{t.d(r,{Zo:()=>f,kt:()=>u});var n=t(67294);function i(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function l(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,n)}return t}function o(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?l(Object(t),!0).forEach((function(r){i(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):l(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function a(e,r){if(null==e)return{};var t,n,i=function(e,r){if(null==e)return{};var t,n,i={},l=Object.keys(e);for(n=0;n<l.length;n++)t=l[n],r.indexOf(t)>=0||(i[t]=e[t]);return i}(e,r);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(n=0;n<l.length;n++)t=l[n],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var p=n.createContext({}),c=function(e){var r=n.useContext(p),t=r;return e&&(t="function"==typeof e?e(r):o(o({},r),e)),t},f=function(e){var r=c(e.components);return n.createElement(p.Provider,{value:r},e.children)},s="mdxType",d={inlineCode:"code",wrapper:function(e){var r=e.children;return n.createElement(n.Fragment,{},r)}},m=n.forwardRef((function(e,r){var t=e.components,i=e.mdxType,l=e.originalType,p=e.parentName,f=a(e,["components","mdxType","originalType","parentName"]),s=c(t),m=i,u=s["".concat(p,".").concat(m)]||s[m]||d[m]||l;return t?n.createElement(u,o(o({ref:r},f),{},{components:t})):n.createElement(u,o({ref:r},f))}));function u(e,r){var t=arguments,i=r&&r.mdxType;if("string"==typeof e||i){var l=t.length,o=new Array(l);o[0]=m;var a={};for(var p in r)hasOwnProperty.call(r,p)&&(a[p]=r[p]);a.originalType=e,a[s]="string"==typeof e?e:i,o[1]=a;for(var c=2;c<l;c++)o[c]=t[c];return n.createElement.apply(null,o)}return n.createElement.apply(null,t)}m.displayName="MDXCreateElement"},69466:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>p,contentTitle:()=>o,default:()=>d,frontMatter:()=>l,metadata:()=>a,toc:()=>c});var n=t(87462),i=(t(67294),t(3905));const l={title:"minder profile"},o=void 0,a={unversionedId:"ref/cli/minder_profile",id:"ref/cli/minder_profile",title:"minder profile",description:"minder profile",source:"@site/docs/ref/cli/minder_profile.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_profile",permalink:"/ref/cli/minder_profile",draft:!1,tags:[],version:"current",frontMatter:{title:"minder profile"},sidebar:"minder",previous:{title:"minder docs",permalink:"/ref/cli/minder_docs"},next:{title:"minder profile create",permalink:"/ref/cli/minder_profile_create"}},p={},c=[{value:"minder profile",id:"minder-profile",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],f={toc:c},s="wrapper";function d(e){let{components:r,...t}=e;return(0,i.kt)(s,(0,n.Z)({},f,t,{components:r,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"minder-profile"},"minder profile"),(0,i.kt)("p",null,"Manage profiles within a minder control plane"),(0,i.kt)("h3",{id:"synopsis"},"Synopsis"),(0,i.kt)("p",null,"The minder profile subcommands allows the management of profiles within\na minder controlplane."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -h, --help   help for profile\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "staging.stacklok.dev")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "minder-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.staging.stacklok.dev")\n')),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder"},"minder"),"\t - Minder controls the hosted minder service"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_profile_create"},"minder profile create"),"\t - Create a profile within a minder control plane"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_profile_delete"},"minder profile delete"),"\t - Delete a profile within a minder control plane"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_profile_get"},"minder profile get"),"\t - Get details for a profile within a minder control plane"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/ref/cli/minder_profile_list"},"minder profile list"),"\t - List profiles within a minder control plane")))}d.isMDXComponent=!0}}]);