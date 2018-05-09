(function(a){a.su.Widget("editor",{defaults:{columns:null,grid:null,editing:false,pluginId:"",items:null,listId:null,form:null},create:function(e,b){var d=this;d.each(function(o,n){a.extend(this,e,b);var p=a(n),m=n.columns;var f='<td class="editor-container" colspan="'+m.length+'">';f+='<div class="container editor-content-container"></div>';f+='<div class="container editor-buttons-container">';f+='<div class="button-container">';f+='<button type="button" class="editor-btn btn-submit button-button">'+a.su.CHAR.OPERATION.OK+"</button>";f+="</div>";f+='<div class="button-container">';f+='<button type="button" class="editor-btn btn-delete button-button">'+a.su.CHAR.OPERATION.DELETE+"</button>";f+="</div>";f+='<div class="button-container">';f+='<button type="button" class="editor-btn btn-cancel button-button">'+a.su.CHAR.OPERATION.CANCEL+"</button>";f+="</div>";f+="</div>";f+="</td>";var j=a(f);p.append(j).addClass("container widget-container editor-container");var k=p.find("div.editor-content-container");var q=[];for(var s=0;s<m.length;s++){var l=m[s],g=m[s]["editor"];if(g){var r=a("<input />");k.append(r);if(a.type(g)==="string"){r[g]({fieldLabel:l.text||"",name:l.name||l.dataIndex||""})}else{if(g.xtype){var h=a.extend({},g,{fieldLabel:l.text||"",name:l.name||l.dataIndex||""});r[g.xtype](h)}else{console.error("Invalid Editor type!");return null}}q.push({name:l.name||l.dataIndex||""})}}a.extend(b,{fields:q});j.form(b);n.pluginId=a.su.randomId("editor");n.isEditor=true});d.delegate("button.btn-submit","click",function(f){f.stopPropagation();d.editor("completeEdit")});d.delegate("button.btn-delete","click",function(f){});d.delegate("button.btn-cancel","click",function(f){f.stopPropagation();d.editor("cancelEdit")});var c=d.get(0).grid;if(!c||c.length==0||!c.get(0).isGrid){console.error("Invalid grid for the editor!");return null}c.delegate("a.grid-content-btn.btn-edit","click",function(g){g.preventDefault();g.stopPropagation();var f=a(this).attr("data-key");editor=d;if(editor){var h=editor.get(0);if(h&&h.isEditor){if(h.editing===false){editor.editor("startEdit",f)}else{editor.editor("shake")}}}}).delegate("a.grid-content-btn.btn-delete","click",function(h){h.preventDefault();h.stopPropagation();var f=a(this).attr("data-key"),g=d;if(g){var i=g.get(0);if(i&&i.isEditor){if(i.editing===false){store=c.get(0).store;store.remove([f])}else{g.editor("shake")}}}});d.css("display","none");return d},hide:function(b){var b=b||this;b.detach().css("display","none");return b},shake:function(b){var b=b||this;b.queue(function(){a(this).addClass("shaking");a(this).dequeue()});b.delay(80);b.queue(function(){a(this).removeClass("shaking");a(this).dequeue()});b.delay(80);b.queue(function(){a(this).addClass("shaking");a(this).dequeue()});b.delay(80);b.queue(function(){a(this).removeClass("shaking");a(this).dequeue()});return b},startEdit:function(h,d){var h=h||this,g=d[1]||"add",b=h.get(0).grid,j=b.get(0).store,i=b.find("tbody.grid-content-data"),f=null,c=h.find("td.editor-container");h.get(0).listId=g;h.editor("hide");h.get(0).editing=true;if(g!="add"){var e=j.getData(g);if(e){c.form("loadData",e)}else{c.form("reset")}f=i.find("tr.grid-content-tr").filter(".grid-content-tr-"+g).addClass("editing");h.insertAfter(f);h.slideDown(300)}else{c.form("reset");f=i.find("tr.grid-content-tr").eq(0);h.insertBefore(f);h.slideDown(300)}return h},completeEdit:function(e){var e=e||this,f=e.get(0),d=f.grid,c=d.get(0).store,b=f.listId;if(b!="add"){c.update(b,e.form("serialize"),function(g){e.editor("cancelEdit")})}else{c.insert(0,e.form("serialize"),function(g){e.editor("cancelEdit")})}return e},cancelEdit:function(d){var d=d||this,f=d.get(0),c=d.get(0).grid,b=f.listId;var e=null;if(b!="add"){e=c.find("tr.grid-content-tr").filter(".grid-content-tr-"+b);d.editor("hide");e.removeClass("editing")}else{d.editor("hide")}f.editing=false;f.listId=null;return d}})})(jQuery);