"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[4362],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>g});var n=r(67294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var s=n.createContext({}),p=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},c=function(e){var t=p(e.components);return n.createElement(s.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},f=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,a=e.originalType,s=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),u=p(r),f=i,g=u["".concat(s,".").concat(f)]||u[f]||d[f]||a;return r?n.createElement(g,o(o({ref:t},c),{},{components:r})):n.createElement(g,o({ref:t},c))}));function g(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=r.length,o=new Array(a);o[0]=f;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[u]="string"==typeof e?e:i,o[1]=l;for(var p=2;p<a;p++)o[p]=r[p];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}f.displayName="MDXCreateElement"},27880:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>d,frontMatter:()=>a,metadata:()=>l,toc:()=>p});var n=r(87462),i=(r(67294),r(3905));const a={title:"Creating your first profile",sidebar_position:40},o="Creating your first profile",l={unversionedId:"getting_started/first_profile",id:"getting_started/first_profile",title:"Creating your first profile",description:"Minder uses profiles to specify common,",source:"@site/docs/getting_started/first_profile.md",sourceDirName:"getting_started",slug:"/getting_started/first_profile",permalink:"/getting_started/first_profile",draft:!1,tags:[],version:"current",sidebarPosition:40,frontMatter:{title:"Creating your first profile",sidebar_position:40},sidebar:"minder",previous:{title:"Register Repositories",permalink:"/getting_started/register_repos"},next:{title:"Automatic Remediations",permalink:"/getting_started/remediations"}},s={},p=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Creating and applying profiles",id:"creating-and-applying-profiles",level:2},{value:"Viewing alerts",id:"viewing-alerts",level:2},{value:"Delete registered repositories",id:"delete-registered-repositories",level:2}],c={toc:p},u="wrapper";function d(e){let{components:t,...r}=e;return(0,i.kt)(u,(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"creating-your-first-profile"},"Creating your first profile"),(0,i.kt)("p",null,"Minder uses ",(0,i.kt)("a",{parentName:"p",href:"/how-to/create_profile"},"profiles")," to specify common,\nconsistent configuration which should be enforced on all registered\nrepositories.  In this tutorial, you will register a GitHub repository and\ncreate a profile that indicates whether secret scanning is enabled on the\nregistered repositories."),(0,i.kt)("h2",{id:"prerequisites"},"Prerequisites"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/getting_started/install_cli"},"The ",(0,i.kt)("inlineCode",{parentName:"a"},"minder")," CLI application")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/getting_started/login"},"A Minder account")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/getting_started/login#enrolling-the-github-provider"},"An enrolled GitHub token")," that is either an Owner in the organization or an Admin on the repositories"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/getting_started/register_repos"},"One or more repositories registered with Minder"))),(0,i.kt)("h2",{id:"creating-and-applying-profiles"},"Creating and applying profiles"),(0,i.kt)("p",null,"A profile is a set of rules that you apply to your registered repositories.\nBefore creating a profile, you need to ensure that all desired rule_types have been created in Minder."),(0,i.kt)("p",null,"Start by creating a rule that checks if secret scanning is enabled and creates\na security advisory alert if secret scanning is not enabled.",(0,i.kt)("br",{parentName:"p"}),"\n","This is a reference rule provided by the Minder team in the ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/stacklok/minder-rules-and-profiles"},"minder-rules-and-profiles repository"),"."),(0,i.kt)("p",null,"For this exercise, we're going to download just the ",(0,i.kt)("inlineCode",{parentName:"p"},"secret_scanning.yaml"),"\nrule, and then use ",(0,i.kt)("inlineCode",{parentName:"p"},"minder rule_type create")," to define the secret scanning rule."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"curl -LO https://raw.githubusercontent.com/stacklok/minder-rules-and-profiles/main/rule-types/github/secret_scanning.yaml\n")),(0,i.kt)("p",null,"Once you've downloaded the rule definition, you can create it in your Minder account:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder rule_type create -f secret_scanning.yaml\n")),(0,i.kt)("p",null,"Next, create a profile that applies the secret scanning rule."),(0,i.kt)("p",null,"Create a new file called ",(0,i.kt)("inlineCode",{parentName:"p"},"profile.yaml"),".\nPaste the following profile definition into the newly created file."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},'---\nversion: v1\ntype: profile\nname: github-profile\ncontext:\n  provider: github\nalert: "on"\nremediate: "off"\nrepository:\n  - type: secret_scanning\n    def:\n      enabled: true\n')),(0,i.kt)("p",null,"Create the profile in Minder:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile create -f profile.yaml\n")),(0,i.kt)("p",null,"Check the status of the profile:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile_status list --profile github-profile\n")),(0,i.kt)("p",null,"If all registered repositories have secret scanning enabled, you will see the ",(0,i.kt)("inlineCode",{parentName:"p"},"OVERALL STATUS")," is ",(0,i.kt)("inlineCode",{parentName:"p"},"Success"),", otherwise the\noverall status is ",(0,i.kt)("inlineCode",{parentName:"p"},"Failure"),"."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"+--------------------------------------+----------------+----------------+----------------------+\n|                  ID                  |      NAME      | OVERALL STATUS |     LAST UPDATED     |\n+--------------------------------------+----------------+----------------+----------------------+\n| 1abcae55-5eb8-4d9e-847c-18e605fbc1cc | github-profile | \u2705 Success     | 2023-11-06T17:42:04Z |\n+--------------------------------------+----------------+----------------+----------------------+\n")),(0,i.kt)("p",null,"If secret scanning is not enabled, you will see ",(0,i.kt)("inlineCode",{parentName:"p"},"\u274c Failure")," instead of ",(0,i.kt)("inlineCode",{parentName:"p"},"\u2705 Success"),"."),(0,i.kt)("p",null,"See a detailed view of which repositories satisfy the secret scanning rule:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"minder profile_status list --profile github-profile --detailed\n")),(0,i.kt)("h2",{id:"viewing-alerts"},"Viewing alerts"),(0,i.kt)("p",null,"Disable secret scanning in one of the registered repositories, by following\n",(0,i.kt)("a",{parentName:"p",href:"https://docs.github.com/en/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories"},"these instructions provided by GitHub"),"."),(0,i.kt)("p",null,"Navigate to the repository on GitHub, click on the Security tab and view the Security Advisories.",(0,i.kt)("br",{parentName:"p"}),"\n","Notice that there is a new advisory titled ",(0,i.kt)("inlineCode",{parentName:"p"},"minder: profile github-profile failed with rule secret_scanning"),"."),(0,i.kt)("p",null,"Enable secret scanning in the same registered repository, by following\n",(0,i.kt)("a",{parentName:"p",href:"https://docs.github.com/en/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories"},"these instructions provided by GitHub"),"."),(0,i.kt)("p",null,"Navigate to the repository on GitHub, click on the Security tab and view the Security Advisories.\nNotice that the advisory titled ",(0,i.kt)("inlineCode",{parentName:"p"},"minder: profile github-profile failed with rule secret_scanning")," is now closed."),(0,i.kt)("h2",{id:"delete-registered-repositories"},"Delete registered repositories"),(0,i.kt)("p",null,"If you want to stop monitoring a repository, you can delete it from Minder by using the ",(0,i.kt)("inlineCode",{parentName:"p"},"repo delete")," command:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"minder repo delete --provider github --name $REPO_NAME\n")),(0,i.kt)("p",null,"where ",(0,i.kt)("inlineCode",{parentName:"p"},"$REPO_NAME")," is the fully-qualified name (",(0,i.kt)("inlineCode",{parentName:"p"},"owner/name"),") of the repository you wish to delete, for example ",(0,i.kt)("inlineCode",{parentName:"p"},"testorg/testrepo"),"."),(0,i.kt)("p",null,"This will delete the repository from Minder and remove the webhook from the repository."))}d.isMDXComponent=!0}}]);