let S=0,X=`function`,Z=`Object`,a0=4,W=1,$=16,P=`utf-8`,O=`undefined`,R=null,Y=`string`,U=Array,Q=Error,_=FinalizationRegistry,a1=Object,a2=Promise,T=Uint8Array,V=undefined;var x=((a,b)=>{const c=b(a.length*W,W)>>>S;e().set(a,c/W);m=a.length;return c});var j=(a=>g[a]);var p=((a,b,c)=>{if(c===V){const c=n.encode(a);const d=b(c.length,W)>>>S;e().subarray(d,d+ c.length).set(c);m=c.length;return d};let d=a.length;let f=b(d,W)>>>S;const g=e();let h=S;for(;h<d;h++){const b=a.charCodeAt(h);if(b>127)break;g[f+ h]=b};if(h!==d){if(h!==S){a=a.slice(h)};f=c(f,d,d=h+ a.length*3,W)>>>S;const b=e().subarray(f+ h,f+ d);const g=o(a,b);h+=g.written;f=c(f,d,h,W)>>>S};m=h;return f});var J=(()=>{const c={};c.wbg={};c.wbg.__wbg_createTextNode_0c38fd80a5b2284d=((a,b,c)=>{var d=z(b,c);const e=j(a).createTextNode(d);return i(e)});c.wbg.__wbindgen_string_new=((a,b)=>{const c=f(a,b);return i(c)});c.wbg.__wbindgen_object_drop_ref=(a=>{l(a)});c.wbg.__wbg_body_edb1908d3ceff3a1=(a=>{const b=j(a).body;return q(b)?S:i(b)});c.wbg.__wbindgen_object_clone_ref=(a=>{const b=j(a);return i(b)});c.wbg.__wbg_createDocumentFragment_8c86903bbb0a3c3c=(a=>{const b=j(a).createDocumentFragment();return i(b)});c.wbg.__wbg_append_7ba9d5c2eb183eea=function(){return A(((a,b)=>{j(a).append(j(b))}),arguments)};c.wbg.__wbg_new_72fb9a18b5ae2624=(()=>{const a=new a1();return i(a)});c.wbg.__wbg_new_ab6fd82b10560829=function(){return A((()=>{const a=new Headers();return i(a)}),arguments)};c.wbg.__wbg_newwithstrandinit_3fd6fba4083ff2d0=function(){return A(((a,b,c)=>{var d=z(a,b);const e=new Request(d,j(c));return i(e)}),arguments)};c.wbg.__wbg_fetch_c4b6afebdb1f918e=((a,b)=>{const c=j(a).fetch(j(b));return i(c)});c.wbg.__wbg_instanceof_Response_849eb93e75734b6e=(a=>{let b;try{b=j(a) instanceof Response}catch(a){b=!1}const c=b;return c});c.wbg.__wbg_text_450a059667fd91fd=function(){return A((a=>{const b=j(a).text();return i(b)}),arguments)};c.wbg.__wbg_signschnorr_8a56b9c37020b9ab=(b=>{const c=a(j(b));return i(c)});c.wbg.__wbindgen_string_get=((a,c)=>{const d=j(c);const e=typeof d===Y?d:V;var f=q(e)?S:p(e,b.__wbindgen_export_0,b.__wbindgen_export_1);var g=m;s()[a/a0+ W]=g;s()[a/a0+ S]=f});c.wbg.__wbg_new_81740750da40724f=((a,b)=>{try{var c={a:a,b:b};var d=(a,b)=>{const d=c.a;c.a=S;try{return B(d,c.b,a,b)}finally{c.a=d}};const e=new a2(d);return i(e)}finally{c.a=c.b=S}});c.wbg.__wbg_new_abda76e883ba8a5f=(()=>{const a=new Q();return i(a)});c.wbg.__wbg_stack_658279fe44541cf6=((a,c)=>{const d=j(c).stack;const e=p(d,b.__wbindgen_export_0,b.__wbindgen_export_1);const f=m;s()[a/a0+ W]=f;s()[a/a0+ S]=e});c.wbg.__wbg_error_f851667af71bcfc6=((a,c)=>{var d=z(a,c);if(a!==S){b.__wbindgen_export_4(a,c,W)};console.error(d)});c.wbg.__wbg_instanceof_Error_e20bb56fd5591a93=(a=>{let b;try{b=j(a) instanceof Q}catch(a){b=!1}const c=b;return c});c.wbg.__wbg_name_e7429f0dda6079e2=(a=>{const b=j(a).name;return i(b)});c.wbg.__wbg_message_5bf28016c2b49cfb=(a=>{const b=j(a).message;return i(b)});c.wbg.__wbg_toString_ffe4c9ea3b3532e9=(a=>{const b=j(a).toString();return i(b)});c.wbg.__wbg_self_ce0dbfc45cf2f5be=function(){return A((()=>{const a=self.self;return i(a)}),arguments)};c.wbg.__wbg_window_c6fb939a7f436783=function(){return A((()=>{const a=window.window;return i(a)}),arguments)};c.wbg.__wbg_globalThis_d1e6af4856ba331b=function(){return A((()=>{const a=globalThis.globalThis;return i(a)}),arguments)};c.wbg.__wbg_global_207b558942527489=function(){return A((()=>{const a=global.global;return i(a)}),arguments)};c.wbg.__wbindgen_is_undefined=(a=>{const b=j(a)===V;return b});c.wbg.__wbg_newnoargs_e258087cd0daa0ea=((a,b)=>{var c=z(a,b);const d=new Function(c);return i(d)});c.wbg.__wbg_call_27c0f87801dedf93=function(){return A(((a,b)=>{const c=j(a).call(j(b));return i(c)}),arguments)};c.wbg.__wbg_call_b3ca7c6051f9bec1=function(){return A(((a,b,c)=>{const d=j(a).call(j(b),j(c));return i(d)}),arguments)};c.wbg.__wbg_set_1f9b04f170055d33=function(){return A(((a,b,c)=>{const d=Reflect.set(j(a),j(b),j(c));return d}),arguments)};c.wbg.__wbg_before_210596e44d88649f=function(){return A(((a,b)=>{j(a).before(j(b))}),arguments)};c.wbg.__wbg_is_010fdc0f4ab96916=((a,b)=>{const c=a1.is(j(a),j(b));return c});c.wbg.__wbg_nextSibling_709614fdb0fb7a66=(a=>{const b=j(a).nextSibling;return q(b)?S:i(b)});c.wbg.__wbg_childNodes_118168e8b23bcb9b=(a=>{const b=j(a).childNodes;return i(b)});c.wbg.__wbg_length_d0a802565d17eec4=(a=>{const b=j(a).length;return b});c.wbg.__wbg_document_5100775d18896c16=(a=>{const b=j(a).document;return q(b)?S:i(b)});c.wbg.__wbg_createElement_8bae7856a4bb7411=function(){return A(((a,b,c)=>{var d=z(b,c);const e=j(a).createElement(d);return i(e)}),arguments)};c.wbg.__wbg_createComment_354ccab4fdc521ee=((a,b,c)=>{var d=z(b,c);const e=j(a).createComment(d);return i(e)});c.wbg.__wbindgen_debug_string=((a,c)=>{const d=t(j(c));const e=p(d,b.__wbindgen_export_0,b.__wbindgen_export_1);const f=m;s()[a/a0+ W]=f;s()[a/a0+ S]=e});c.wbg.__wbindgen_throw=((a,b)=>{throw new Q(f(a,b))});c.wbg.__wbindgen_cb_drop=(a=>{const b=l(a).original;if(b.cnt--==W){b.a=S;return !0};const c=!1;return c});c.wbg.__wbg_then_0c86a60e8fcfe9f6=((a,b)=>{const c=j(a).then(j(b));return i(c)});c.wbg.__wbg_queueMicrotask_481971b0d87f3dd4=(a=>{queueMicrotask(j(a))});c.wbg.__wbg_then_a73caa9a87991566=((a,b,c)=>{const d=j(a).then(j(b),j(c));return i(d)});c.wbg.__wbg_queueMicrotask_3cbae2ec6b6cd3d6=(a=>{const b=j(a).queueMicrotask;return i(b)});c.wbg.__wbindgen_is_function=(a=>{const b=typeof j(a)===X;return b});c.wbg.__wbg_resolve_b0083a7967828ec8=(a=>{const b=a2.resolve(j(a));return i(b)});c.wbg.__wbg_byobRequest_72fca99f9c32c193=(a=>{const b=j(a).byobRequest;return q(b)?S:i(b)});c.wbg.__wbg_view_7f0ce470793a340f=(a=>{const b=j(a).view;return q(b)?S:i(b)});c.wbg.__wbg_byteLength_58f7b4fab1919d44=(a=>{const b=j(a).byteLength;return b});c.wbg.__wbg_close_184931724d961ccc=function(){return A((a=>{j(a).close()}),arguments)};c.wbg.__wbg_new_28c511d9baebfa89=((a,b)=>{var c=z(a,b);const d=new Q(c);return i(d)});c.wbg.__wbg_buffer_dd7f74bc60f1faab=(a=>{const b=j(a).buffer;return i(b)});c.wbg.__wbg_byteOffset_81d60f7392524f62=(a=>{const b=j(a).byteOffset;return b});c.wbg.__wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb=((a,b,c)=>{const d=new T(j(a),b>>>S,c>>>S);return i(d)});c.wbg.__wbg_length_c20a40f15020d68a=(a=>{const b=j(a).length;return b});c.wbg.__wbindgen_memory=(()=>{const a=b.memory;return i(a)});c.wbg.__wbg_buffer_12d079cc21e14bdb=(a=>{const b=j(a).buffer;return i(b)});c.wbg.__wbg_set_a47bac70306a19a7=((a,b,c)=>{j(a).set(j(b),c>>>S)});c.wbg.__wbg_close_a994f9425dab445c=function(){return A((a=>{j(a).close()}),arguments)};c.wbg.__wbg_enqueue_ea194723156c0cc2=function(){return A(((a,b)=>{j(a).enqueue(j(b))}),arguments)};c.wbg.__wbg_instanceof_Window_f401953a2cf86220=(a=>{let b;try{b=j(a) instanceof Window}catch(a){b=!1}const c=b;return c});c.wbg.__wbg_appendChild_580ccb11a660db68=function(){return A(((a,b)=>{const c=j(a).appendChild(j(b));return i(c)}),arguments)};c.wbg.__wbg_cloneNode_e19c313ea20d5d1d=function(){return A((a=>{const b=j(a).cloneNode();return i(b)}),arguments)};c.wbg.__wbg_respond_b1a43b2e3a06d525=function(){return A(((a,b)=>{j(a).respond(b>>>S)}),arguments)};c.wbg.__wbg_debug_5fb96680aecf5dc8=(a=>{console.debug(j(a))});c.wbg.__wbg_error_8e3928cfb8a43e2b=(a=>{console.error(j(a))});c.wbg.__wbg_info_530a29cb2e4e3304=(a=>{console.info(j(a))});c.wbg.__wbg_log_5bb5f88f245d7762=(a=>{console.log(j(a))});c.wbg.__wbg_warn_63bbae1730aead09=(a=>{console.warn(j(a))});c.wbg.__wbindgen_closure_wrapper1543=((a,b,c)=>{const d=v(a,b,103,w);return i(d)});return c});var N=(async(a)=>{if(b!==V)return b;if(typeof a===O){a=new URL(`liqstr_bg.wasm`,import.meta.url)};const c=J();if(typeof a===Y||typeof Request===X&&a instanceof Request||typeof URL===X&&a instanceof URL){a=fetch(a)};K(c);const {instance:d,module:e}=await I(await a,c);return L(d,e)});var M=(a=>{if(b!==V)return b;const c=J();K(c);if(!(a instanceof WebAssembly.Module)){a=new WebAssembly.Module(a)};const d=new WebAssembly.Instance(a,c);return L(d,a)});var B=((a,c,d,e)=>{b.__wbindgen_export_6(a,c,i(d),i(e))});var l=(a=>{const b=j(a);k(a);return b});var v=((a,c,d,e)=>{const f={a:a,b:c,cnt:W,dtor:d};const g=(...a)=>{f.cnt++;const c=f.a;f.a=S;try{return e(c,f.b,...a)}finally{if(--f.cnt===S){b.__wbindgen_export_2.get(f.dtor)(c,f.b);u.unregister(f)}else{f.a=c}}};g.original=f;u.register(g,f,f);return g});var f=((a,b)=>{a=a>>>S;return c.decode(e().subarray(a,a+ b))});var I=(async(a,b)=>{if(typeof Response===X&&a instanceof Response){if(typeof WebAssembly.instantiateStreaming===X){try{return await WebAssembly.instantiateStreaming(a,b)}catch(b){if(a.headers.get(`Content-Type`)!=`application/wasm`){console.warn(`\`WebAssembly.instantiateStreaming\` failed because your server does not serve wasm with \`application/wasm\` MIME type. Falling back to \`WebAssembly.instantiate\` which is slower. Original error:\\n`,b)}else{throw b}}};const c=await a.arrayBuffer();return await WebAssembly.instantiate(c,b)}else{const c=await WebAssembly.instantiate(a,b);if(c instanceof WebAssembly.Instance){return {instance:c,module:a}}else{return c}}});var q=(a=>a===V||a===R);var z=((a,b)=>{if(a===S){return j(b)}else{return f(a,b)}});var t=(a=>{const b=typeof a;if(b==`number`||b==`boolean`||a==R){return `${a}`};if(b==Y){return `"${a}"`};if(b==`symbol`){const b=a.description;if(b==R){return `Symbol`}else{return `Symbol(${b})`}};if(b==X){const b=a.name;if(typeof b==Y&&b.length>S){return `Function(${b})`}else{return `Function`}};if(U.isArray(a)){const b=a.length;let c=`[`;if(b>S){c+=t(a[S])};for(let d=W;d<b;d++){c+=`, `+ t(a[d])};c+=`]`;return c};const c=/\[object ([^\]]+)\]/.exec(toString.call(a));let d;if(c.length>W){d=c[W]}else{return toString.call(a)};if(d==Z){try{return `Object(`+ JSON.stringify(a)+ `)`}catch(a){return Z}};if(a instanceof Q){return `${a.name}: ${a.message}\n${a.stack}`};return d});function A(a,c){try{return a.apply(this,c)}catch(a){b.__wbindgen_export_5(i(a))}}var s=(()=>{if(r===R||r.byteLength===S){r=new Int32Array(b.memory.buffer)};return r});var w=((a,c,d)=>{b.__wbindgen_export_3(a,c,i(d))});var k=(a=>{if(a<132)return;g[a]=h;h=a});var i=(a=>{if(h===g.length)g.push(g.length+ W);const b=h;h=g[b];g[b]=a;return b});var K=((a,b)=>{});var e=(()=>{if(d===R||d.byteLength===S){d=new T(b.memory.buffer)};return d});var L=((a,c)=>{b=a.exports;N.__wbindgen_wasm_module=c;r=R;d=R;b.__wbindgen_start();return b});import{sign_schnorr as a}from"./snippets/liqstr-47cb0f282df81fdb/inline0.js";let b;const c=typeof TextDecoder!==O?new TextDecoder(P,{ignoreBOM:!0,fatal:!0}):{decode:()=>{throw Q(`TextDecoder not available`)}};if(typeof TextDecoder!==O){c.decode()};let d=R;const g=new U(128).fill(V);g.push(V,R,!0,!1);let h=g.length;let m=S;const n=typeof TextEncoder!==O?new TextEncoder(P):{encode:()=>{throw Q(`TextEncoder not available`)}};const o=typeof n.encodeInto===X?((a,b)=>n.encodeInto(a,b)):((a,b)=>{const c=n.encode(a);b.set(c);return {read:a.length,written:c.length}});let r=R;const u=typeof _===O?{register:()=>{},unregister:()=>{}}:new _(a=>{b.__wbindgen_export_2.get(a.dtor)(a.a,a.b)});function y(a){const c=x(a,b.__wbindgen_export_0);const d=m;const e=b.sign_hash(c,d);return l(e)}const C=typeof _===O?{register:()=>{},unregister:()=>{}}:new _(a=>b.__wbg_intounderlyingbytesource_free(a>>>S));class D{__destroy_into_raw(){const a=this.__wbg_ptr;this.__wbg_ptr=S;C.unregister(this);return a}free(){const a=this.__destroy_into_raw();b.__wbg_intounderlyingbytesource_free(a)}type(){try{const e=b.__wbindgen_add_to_stack_pointer(-$);b.intounderlyingbytesource_type(e,this.__wbg_ptr);var a=s()[e/a0+ S];var c=s()[e/a0+ W];var d=z(a,c);if(a!==S){b.__wbindgen_export_4(a,c,W)};return d}finally{b.__wbindgen_add_to_stack_pointer($)}}autoAllocateChunkSize(){const a=b.intounderlyingbytesource_autoAllocateChunkSize(this.__wbg_ptr);return a>>>S}start(a){b.intounderlyingbytesource_start(this.__wbg_ptr,i(a))}pull(a){const c=b.intounderlyingbytesource_pull(this.__wbg_ptr,i(a));return l(c)}cancel(){const a=this.__destroy_into_raw();b.intounderlyingbytesource_cancel(a)}}const E=typeof _===O?{register:()=>{},unregister:()=>{}}:new _(a=>b.__wbg_intounderlyingsink_free(a>>>S));class F{__destroy_into_raw(){const a=this.__wbg_ptr;this.__wbg_ptr=S;E.unregister(this);return a}free(){const a=this.__destroy_into_raw();b.__wbg_intounderlyingsink_free(a)}write(a){const c=b.intounderlyingsink_write(this.__wbg_ptr,i(a));return l(c)}close(){const a=this.__destroy_into_raw();const c=b.intounderlyingsink_close(a);return l(c)}abort(a){const c=this.__destroy_into_raw();const d=b.intounderlyingsink_abort(c,i(a));return l(d)}}const G=typeof _===O?{register:()=>{},unregister:()=>{}}:new _(a=>b.__wbg_intounderlyingsource_free(a>>>S));class H{__destroy_into_raw(){const a=this.__wbg_ptr;this.__wbg_ptr=S;G.unregister(this);return a}free(){const a=this.__destroy_into_raw();b.__wbg_intounderlyingsource_free(a)}pull(a){const c=b.intounderlyingsource_pull(this.__wbg_ptr,i(a));return l(c)}cancel(){const a=this.__destroy_into_raw();b.intounderlyingsource_cancel(a)}}export default N;export{y as sign_hash,D as IntoUnderlyingByteSource,F as IntoUnderlyingSink,H as IntoUnderlyingSource,M as initSync}