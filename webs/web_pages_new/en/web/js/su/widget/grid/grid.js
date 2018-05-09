(function(a){a.su.Widget("grid",{defaults:{cls:"",columns:[],bottom_tbar:false,store:null,operation:null,sortable:false,minLines:4,paging:null,editor:null,update:"complete",autoRefresh:false},create:function(f,c){var d=this;d.each(function(p,o){var q=a(o);a.extend(this,f,c);o.id=o.id||a.su.randomId("gird");if(!o.isPanel){a(o).panel(c).addClass("grid-panel")}var m=this.columns;if(m.length===0){console.error("Please define the columns property!");return false}var k="";if(o.sortable){k='<button class="grid-header-btn btn-sort"></button>'}var j='<style type="text/css">';var h='<div class="container grid-container '+this.cls+'">';h+='<div class="container grid-header-container">';h+="<table>";h+='<tr class="grid-header-tr">';for(var r=0;r<m.length;r++){var l=m[r];l.cls=l.cls||"",l.dataIndex=l.dataIndex||l.name,l.renderer=l.render||function(i){return i};if(l.width){j+="div#"+o.id+" th.grid-header-"+r+",";j+="div#"+o.id+" td.grid-content-td-"+r;j+="{width:"+l.width+"px;}"}var t="";switch(l.xtype){case"checkcolumn":t+='<div class="checkbox-group-container grid-header-checkbox checkcolumn inline">';t+='<div class="widget-wrap">';t+='<label class="checkbox-label">';t+='<input class="" type="checkbox" value=""/>';t+='<span class="icon"></span>';t+="</label>";t+="</div>";t+="</div>";l.text=l.text||a.su.CHAR.GRID.SELECTED;break;case"rownumberer":l.text=l.text||a.su.CHAR.GRID.ID;break;case"settings":l.text=l.text||a.su.CHAR.GRID.MODIFY;break;case"choose":l.text=l.text||"Choose";break;default:l.text=l.text||"";l.name=l.name||l.dataIndex}h+='<th class="grid-header grid-header-'+r+" "+l.dataIndex+'" name="'+l.dataIndex+'">';h+=t;h+='<span class="content">'+l.text+"</span>";h+=k;h+="</th>"}h+="</tr>";h+="</table>";h+="</div>";h+='<div class="grid-content-container">';h+='<table class="grid-content-bg">';h+="<tbody>";for(var r=0;r<o.minLines;r++){h+='<tr class="grid-content-tr grid-content-tr-'+r+'" >';for(var n=0;n<m.length;n++){var l=m[n];h+='<td class="grid-content-td grid-content-td-'+n+" grid-content-td-"+l.dataIndex+'" name="'+l.dataIndex+'">';h+='<span class="content"></span>';h+="</td>"}h+="</tr>"}h+="</tbody>";h+="</table>";h+="<table>";h+='<tbody class="grid-content-data"></tbody>';h+="</table>";h+="</div>";h+="</div>";var g=a(h);a(o).find("div.panel-content-container").append(g);var s=parseInt(a("td.grid-content-td").css("height"),10);if(o.minLines){j+="div#"+o.id+" div.grid-container div.grid-content-container{min-height:"+(s*o.minLines)+"px;}"}j+="</style>";g.prepend(a(j));if(!o.store){console.error("Debug: Grid without store!");return null}else{if(!o.store.isStore){o.store=new a.su.Store(o.store)}}this.isGrid=true;if(o.operation){q.grid("initTBar")}if(o.editor){q.grid("initEditor")}if(o.paging){q.grid("initPaging")}});var e=d.get(0),b=a(e.store);b.on("ev_insertdata",function(j,h,i){var g=e.paging;if(g&&g.get&&g.isPaging){}else{d.grid("insert",h,i)}}).on("ev_loaddata",function(i,h){var g=d.get(0).paging;if(g&&g.isPaging){a(g).paging("loadPage")}else{d.grid("load",h)}}).on("ev_updatedata",function(k,i,h,j){var g=e.paging;if(g&&g.get&&g.isPaging){}else{d.grid("update",i,h,j)}}).on("ev_removedata",function(j,g,i){var h=e.paging;if(h&&h.get&&h.isPaging){}else{d.grid("remove",g)}});d.delegate("tr.grid-content-tr","click",function(h){h.stopPropagation();h.preventDefault();var g=a(this);if(h.shiftKey){g.toggleClass("selected")}else{d.find("tr.grid-content-tr").removeClass("selected");g.addClass("selected")}}).delegate("td.grid-content-td label.checkbox-label","click",function(g){g.stopPropagation();g.preventDefault();a(this).closest("tr.grid-content-tr").toggleClass("selected")}).delegate("th.grid-header div.checkcolumn label.checkbox-label","click",function(h){h.stopPropagation();h.preventDefault();var g=a(this).closest("div.checkbox-group-container");if(g.hasClass("selected")){d.find("tr.grid-content-tr").removeClass("selected");g.removeClass("selected")}else{d.find("tr.grid-content-tr").addClass("selected");g.addClass("selected")}});return d},initRow:function(u,s){var u=u||this,l=u.get(0),t=s[1]||0,x=s[2],y=x[l.store.keyProperty],b=u.grid("getColumns");var m='<tr class="grid-content-tr grid-content-tr-'+y+'" data-key="'+y+'" >';var q=b.length,v=[];for(var n=0;n<q;n++){var c=b[n];switch(c.xtype){case"rownumberer":m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-row-numberer" name="row-numberer">';m+='<span class="grid-row-numberer content">'+(t+1)+"</span>";m+="</td>";break;case"checkcolumn":m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-check-column" name="check-column">';m+='<div class="checkbox-group-container">';m+='<div class="widget-wrap">';m+='<label class="checkbox-label">';m+='<input class="" type="checkbox" value="'+y+'"/>';m+='<span class="icon"></span>';m+="</label>";m+="</div>";m+="</div>";m+="</td>";break;case"statuscolumn":var z=(x[c.dataIndex])?a.su.CHAR.GRID.ENABLED:a.su.CHAR.GRID.DISABLED;m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-status-column" name="check-column">';m+='<span class="grid-row-status-column content">'+z+"</span>";m+="</td>";break;case"settings":m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-settings-column" name="check-column">';m+='<a href="javascript:void(0);" data-key="'+y+'" class="grid-content-btn btn-edit">'+a.su.CHAR.OPERATION.EDIT+"</a>";m+='<a href="javascript:void(0);" data-key="'+y+'" class="grid-content-btn btn-delete">'+a.su.CHAR.OPERATION.DELETE+"</a>";m+="</td>";break;case"choose":m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-settings-column" name="check-column">';m+='<a href="javascript:void(0);" data-key="'+y+'" class="choose-existing-service choose">Choose</a>';m+="</td>";break;case"actioncolumn":var o=c.items;m+='<td class="grid-content-td grid-content-td-'+n+' grid-content-td-action-column" name="action-column">';for(var i=0;i<o.length;i++){var r=o[0];m+='<input class="actioncolumn-input" data-type="'+r.xtype+'" value="'+c.renderer.call(u,x[c.dataIndex])+'" />'}m+="</td>";v.push(n);break;default:m+='<td class="grid-content-td grid-content-td-'+n+" grid-content-td-"+c.name+'" name="'+c.name+'">';m+='<span class="content">'+c.renderer.call(u,x[c.dataIndex])+"</span>";m+="</td>";break}}m+="</tr>";var h=a(m);if(v.length>0){for(var i=0;i<v.length;i++){var k=v[i],o=b[k].items,w=h.find("td.grid-content-td-"+k);var e=w.find("input.actioncolumn-input");for(var d=0;d<o.length;d++){var g={},r=o[d];if(r.properties){var j=r.properties;for(var p=0;p<j.length;p++){var f=j[p];if(f.value===undefined||f.value===null){g[f.property]=f.index}else{g[f.property]=(x[f.index]===f.value)?true:false}}}e.eq(d)[o[d].xtype](a.extend({},o[d],g))}}}return h},initTBar:function(h,e){var h=h||this,f=h.get(0);if(!f){return null}var i=a.type(f.operation);var c=null;if(i==="string"){c=f.operation.split("|")}else{if(i==="array"){c=f.operation}else{return null}}f.operation=c;var b='<div class="operation-container">';for(var g=0;g<c.length;g++){var d=(g===0)?"fst":"";switch(c[g]){case"add":b+='<div class="button-container inline"><button type="button" class="button-button operation-btn btn-add '+d+'"><span class="icon"></span></button></div>';break;case"edit":b+='<div class="button-container inline"><button type="button" class="button-button operation-btn btn-edit '+d+'"><span class="icon"></span></button></div>';break;case"delete":b+='<div class="button-container inline"><button type="button" class="button-button operation-btn btn-delete '+d+'"><span class="icon"></span></button></div>';break;case"enable":b+='<div class="button-container inline"><button type="button" class="button-button operation-btn btn-enable '+d+'"><span class="icon"></span></button></div>';break;case"disable":b+='<div class="button-container inline"><button type="button" class="button-button operation-btn btn-disable '+d+'"><span class="icon"></span></button></div>';break;case"search":b+='<div class="container widget-container text-container search-container inline">';b+='<span class="widget-wrap text-wrap search-wrap">';b+='<input type="text" class="text-text search-text" value="'+a.su.CHAR.OPERATION.SEARCH+'" />';b+='<span class="pos"></span>';b+='<a href="javascript:void(0);" class="search-switch"></a>';b+="</span>";b+="</div>";break;case"refresh":if(f.bottom_tbar){b+='<button type="button" class="operation-refresh middle"></button>'}else{b+='<button type="button" class="operation-refresh '+d+'"></button>'}break;case"autoRefresh":b+='<input class="operation-auto-refresh '+d+'"/>';break;default:if(c[g].xtype){b+='<input operation-index="'+g+'" class="operation-user-defined operation-'+g+" "+d+'"/>'}break}}b+="</div>";var j=a(b);if(f.isPanel){if(f.bottom_tbar){h.panel("getContainer").find("div.panel-tbar-bottom-container").append(j)}else{h.panel("getContainer").find("div.panel-tbar-container").append(j)}j.find("button.operation-refresh").button({text:a.su.CHAR.OPERATION.REFRESH,});j.find("input.operation-auto-refresh").checkbox({fieldLabel:null,items:[{boxlabel:a.su.CHAR.GRID.AUTO_REFRESH,inputvalue:true}]});j.find("input.operation-user-defined").each(function(n){var k=a(this),m=k.attr("operation-index"),l=c[m],o=l.xtype;switch(o){case"display":l=a.extend({fieldLabel:"",labelCls:"s",readOnly:true,inputCls:"xs",value:0},l);k.textbox(l);break;default:l=a.extend(l,{cls:"inline"});k[o](l)}});j.delegate("button.btn-add","click",function(m){m.stopPropagation();m.preventDefault();var l=h.grid("getEditor"),k=h.grid("isEditing");if(k===true){a(l).editor("shake")}else{if(k===false){a(l).editor("startEdit","add")}}}).delegate("button.btn-delete","click",function(m){m.stopPropagation();m.preventDefault();var l=h.grid("getEditor"),k=h.grid("isEditing");if(k===true){a(l).editor("shake")}else{if(k===false){if(selectedKeys.length>0){store.remove(selectedKeys);console.log(store,selectedKeys)}}}}).delegate("button.operation-refresh","click",function(k){k.stopPropagation();k.preventDefault();h.grid("getStore").load()});j.delegate("input.search-text","focus",function(k){k.stopPropagation();a(this).closest("div.search-container").addClass("focus")}).delegate("input.search-text","blur",function(k){k.stopPropagation();a("div.search-container").removeClass("focus")}).delegate("button.operation-btn","mousedown",function(k){k.stopPropagation();a(this).closest("div.button-container").addClass("clicked")}).delegate("a.search-switch","click",function(m){m.stopPropagation();var k=a(this).closest("div.grid-container"),l=a(this).prevAll("input.search-text").val();k.grid("search",l)})}f.operation=j.get(0)},initPaging:function(d,f){var d=d||this,e=d.get(0),b=a.extend(e.paging,{grid:d});if(!e){return null}var c=d.panel("getContainer");e.paging=c.find("div.panel-fbar-container").paging(b).get(0);return d},initEditor:function(c,f){var c=c||this,d=c.get(0);if(!d){return null}var b=d.editor;var e=a('<tr class="editor-container"></tr>').editor({columns:d.columns,grid:c});d.editor=e.get(0);return c},load:function(c,h){var c=c||this,e=c.get(0),d=h[1]||e.store.data,i=isNaN(h[2])?0:h[2],b=isNaN(h[3])?d.length:h[3]+i;var g=c.find("tbody.grid-content-data").empty();for(var f=i;f<b;f++){if(!d[f]){break}g.append(c.grid("initRow",f,d[f]))}c.trigger("ev_load",[d,i,b])},insert:function(d,i){var d=d||this,c=parseInt(i[1],10)||0,e=i[2]||[];if(!a.isArray(e)){e=new Array(e)}var b=e.length;var h=[];for(var g=0;g<b;g++){h.push(d.grid("initRow",c+g,e[g]))}h.reverse();if(c===0){var f=d.find("tr.grid-content-tr").get(0);for(var g=0;g<b;g++){rowObj.insertBefore(h[g])}}else{var f=d.find("tr.grid-content-tr").get(c-1);for(var g=0;g<b;g++){rowObj.insertAfter(h[g])}}d.grid("updateRowNumber")},update:function(l,f){var l=l||this,e=l.get(0).columns,n=f[1],h=f[2]||0,g=f[3];var k=l.find("tr.grid-content-tr-"+n);for(var h=0,i=e.length;h<i;h++){var d=e[h],c=d.xtype,b=d.name,m=d.dataIndex;switch(c){case"rownumberer":break;case"checkcolumn":break;case"settings":break;case"choose":break;case"statuscolumn":var j=(g[m])?a.su.CHAR.GRID.ENABLED:a.su.CHAR.GRID.DISABLED;k.find("td.grid-content-td-status-column span.content").html(j);break;default:k.find("td.grid-content-td-"+b+" span.content").html(d.renderer.call(l,g[m]));break}}return l},remove:function(f,g){var f=f||this,e=g[1]||null;if(e!==null){if(a.type(e)==="number"){e=[e]}for(var d=0,b=e.length;d<b;d++){var c=f.find("tr.grid-content-tr-"+e[d]);c.remove()}f.grid("updateRowNumber")}return f},removeAllData:function(c,d){var c=c||this,b=c.find("div.grid-content-data");b.html("");c.grid("updateRowNumber");return c},updateRowNumber:function(c,f){var c=c||this,d=c.find("tbody.grid-content-data tr.grid-content-tr"),f=parseInt((f[1]||0),10);for(var b=0;b<d.length;b++){var e=a(d.get(b));e.find("span.grid-row-numberer").html(b+1+f)}return c},getColumns:function(b){var b=b||this;return b.get(0).columns},getSelected:function(c){var c=c||this;var d=c.find("tr.grid-content-tr.selected");var b=[];d.each(function(f,g){var e=a(g).attr("data-key");b.push(e)});return b},getStore:function(b){var b=b||this;return b.get(0).store||null},getEditor:function(c){var c=c||this,b=c.get(0).editor;if(b&&a.type(b)==="object"&&b.isEditor===true){return b}else{return undefined}},search:function(c,b){var c=c||this,b=b[1];if(!b){return null}alert(b)},isEditing:function(d){var d=d||this,c=d.grid("getEditor"),b=d.get(0).store;if(c&&c.isEditor){if(c.editing===true){return true}}else{return null}return false}})})(jQuery);