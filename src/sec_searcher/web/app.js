'use strict';
const $ = id => document.getElementById(id);
const labels = {critical:'Критическая',high:'Высокая',medium:'Средняя',low:'Низкая'};
let token = '', report = null, polling = false, submitting = false;
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':token}, body:JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function node(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
async function models() {
  $('refresh').disabled = true;
  try {
    const old = $('model').value, data = await api('/api/models');
    $('model').replaceChildren(...data.models.map(name => {const opt = node('option',name);opt.value=name;return opt;}));
    if (data.models.includes(old)) $('model').value = old;
    if (!data.models.length) throw new Error('Нет загруженной модели. Запустите llama-server с GGUF-файлом.');
    $('message').textContent = '';
  } catch (error) { $('message').textContent = error.message; }
  finally { $('refresh').disabled = false; controls(); }
}
function controls() {
  const running = report?.status === 'running';
  $('start').disabled = submitting || running || !$('model').value || !token;
  $('archive').disabled = submitting || running; $('model').disabled = submitting || running;
  $('mode').disabled = submitting || running;
  $('cancel').hidden = !running;
}
function render() {
  controls();
  if (!report) return;
  $('results').hidden = false;
  const names = {running:report.phase,done:'Проверка завершена',partial:'Частичный отчёт',error:'Не удалось выполнить проверку',cancelled:'Проверка остановлена'};
  $('status').textContent = names[report.status];
  $('progress').max = Math.max(report.total,1); $('progress').value = report.processed;
  $('detail').textContent = `Обработано ${report.processed} из ${report.total} файлов · Без ошибок анализа: ${report.successful} · Пропущено: ${report.skipped.length}` + (report.current_file ? ` · ${report.current_file}` : '');
  if (report.mode==='deep') $('detail').textContent=`Шагов агента: ${report.agent_steps}${report.agent_step_limit?`/${report.agent_step_limit}`:''} · Файлов открыто: ${report.processed}/${report.total} · Прочитано целиком: ${report.successful}`+(report.current_file?` · ${report.current_file}`:'');
  $('counts').replaceChildren(...Object.entries(labels).map(([severity,label]) => {
    const card=node('div',undefined,'count');card.append(node('strong',String(report.findings.filter(f=>f.severity===severity).length),severity),node('span',label));return card;
  }));
  const visible = report.findings.filter(f=>$('severity').value==='all'||f.severity===$('severity').value)
    .sort((a,b)=>Object.keys(labels).indexOf(a.severity)-Object.keys(labels).indexOf(b.severity));
  $('findings').replaceChildren(...visible.map(f=>{
    const card=node('article',undefined,'finding');
    card.append(node('span',labels[f.severity],'severity '+f.severity),node('h3',f.title),node('div',`${f.file}:${f.line}${f.cwe?' · '+f.cwe:''}`,'location'),node('p',f.description),node('p',f.recommendation,'recommendation'));
    for (const evidence of f.evidence||[]) {
      card.append(node('div',`${evidence.file}:${evidence.start_line}–${evidence.end_line}`,'location'),node('pre',evidence.quote,'evidence'));
    }
    return card;
  }));
  if (!visible.length) $('findings').append(node('p',report.status==='running'?'Анализ выполняется. Находки появятся здесь.':report.findings.length?'Нет находок с выбранной критичностью.':report.mode==='deep'?'Сохранённых находок нет. Это не подтверждает безопасность: учитывайте охват, ошибки и ограничения.':report.successful?'В успешно проверенных фрагментах модель не сообщила о проблемах. Учитывайте ошибки и пропуски ниже.':'Нет успешно проверенных файлов. Проверьте ошибки и список пропусков.','empty'));
  $('agent-summary').textContent=report.summary||'';
  $('events-box').hidden=!report.events?.length;
  $('events').replaceChildren(...(report.events||[]).map(e=>node('li',`Шаг ${e.step} · ${e.tool} · ${JSON.stringify(e.args)}${e.error?' · Ошибка: '+e.error:''}`)));
  $('coverage-box').hidden=!report.coverage;
  const coverage=report.coverage;
  $('coverage').replaceChildren(...(coverage?[
    `Прочитано строк: ${coverage.lines_read}/${coverage.lines_total}. Это охват чтения, а не доказательство проверки каждой строки.`,
    ...(report.managed_traversal?['Обход: сервис передаёт очередной непрочитанный фрагмент на каждом шаге.']:[]),
    ...(report.graph?.status==='ready'?[`Граф связей: ${report.graph.nodes} узлов, ${report.graph.edges} связей; ${report.graph.files_with_nodes} файлов с узлами. Построение: ${report.graph.seconds} с. Индексация не считается чтением моделью.`]:[]),
    ...coverage.unread_files.map(f=>'Не прочитан: '+f),...coverage.partially_read_files.map(f=>'Частично прочитан: '+f),...(report.limitations||[])
  ]:[]).map(text=>node('li',text)));
  for (const key of ['errors','skipped']) {
    $(key+'-box').hidden = !report[key].length;
    $(key+'-title').textContent = `${key==='errors'?'Ошибки анализа':'Пропущенные файлы и каталоги'} (${report[key].length})`;
    $(key).replaceChildren(...report[key].map(item=>node('li',`${item.file}${item.lines?':'+item.lines:''} — ${item.error||item.reason}`)));
  }
}
async function poll() {
  if (polling) return;
  polling = true;
  try { report = await api('/api/scan'); render(); }
  catch(error) { $('message').textContent = error.message; }
  finally { polling=false; }
}
$('scan-form').addEventListener('submit', async event=>{
  event.preventDefault();
  if (submitting) return;
  submitting=true; controls(); $('message').textContent='';
  try {
    const file=$('archive').files[0];
    if (!file) throw new Error('Выберите ZIP-архив проекта');
    if (file.size>25*1024*1024) throw new Error('ZIP больше 25 МиБ');
    $('message').textContent='Загрузка и распаковка архива…';
    const response=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'application/zip','X-CSRF-Token':token},body:file});
    const upload=await response.json();
    if (!response.ok) throw new Error(upload.error||'Не удалось загрузить архив');
    await api('/api/scan',{project_id:upload.project_id,model:$('model').value,mode:$('mode').value});
    $('message').textContent='';$('cancel').disabled=false;await poll();
  }
  catch(error){$('message').textContent=error.message;}
  finally {submitting=false;controls();}
});
$('cancel').addEventListener('click',async()=>{
  try {await api('/api/cancel',{});$('cancel').disabled=true;$('message').textContent='Остановка после текущего ответа модели (до 180 секунд).';}
  catch(error){$('message').textContent=error.message;}
});
$('refresh').addEventListener('click',models);
$('severity').addEventListener('change',render);
$('download').addEventListener('click',()=>{
  if (!report) return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
  const a=node('a');a.href=url;a.download='sec-searcher-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
async function init(){
  try {const config=await api('/api/config');token=config.token;await models();await poll();}
  catch(error){$('message').textContent=error.message;}
  setInterval(poll,1500);
}
init();
