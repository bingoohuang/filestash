webpackJsonp([8],{457:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.AppFrame=void 0;var r=function(){function e(e,t){for(var n=0;n<t.length;n++){var r=t[n];r.enumerable=r.enumerable||!1,r.configurable=!0,"value"in r&&(r.writable=!0),Object.defineProperty(e,r.key,r)}}return function(t,n,r){return n&&e(t.prototype,n),r&&e(t,r),t}}(),o=function(e){return e&&e.__esModule?e:{default:e}}(n(0)),a=(n(24),n(5));n(849);t.AppFrame=function(e){function t(e){return function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,t),function(e,t){if(!e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!t||"object"!=typeof t&&"function"!=typeof t?e:t}(this,(t.__proto__||Object.getPrototypeOf(t)).call(this,e))}return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function, not "+typeof t);e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,enumerable:!1,writable:!0,configurable:!0}}),t&&(Object.setPrototypeOf?Object.setPrototypeOf(e,t):e.__proto__=t)}(t,o.default.Component),r(t,[{key:"render",value:function(){var e=null;return this.props.args?this.props.args.endpoint||(e="Missing endpoint configuration. Contact your administrator"):e="Missing configuration. Contact your administrator",null!==e?o.default.createElement("div",{className:"component_appframe"},o.default.createElement("div",{className:"error"},e)):o.default.createElement("div",{className:"component_appframe"},o.default.createElement("iframe",{src:this.props.args.endpoint+"?path="+this.props.data+"&share="+(0,a.currentShare)()}))}}]),t}()},849:function(e,t,n){"use strict";var r=n(895);"string"==typeof r&&(r=[[e.i,r,""]]);var o={hmr:!0,transform:void 0,insertInto:void 0};n(2)(r,o);r.locals&&(e.exports=r.locals)},895:function(e,t,n){(e.exports=n(1)(!1)).push([e.i,".component_appframe {\n  text-align: center;\n  background: #525659;\n  width: 100%; }\n  .component_appframe iframe {\n    width: 100%;\n    height: 100%;\n    border: none; }\n  .component_appframe .error {\n    color: white;\n    font-size: 17px;\n    margin-top: 10px;\n    font-family: monospace; }\n",""])}});