function bindTabs(tabIds, panelIds) {
  const tabs = tabIds.map((id) => document.getElementById(id));
  const panels = panelIds.map((id) => document.getElementById(id));
  if (tabs.some((tab) => !tab) || panels.some((panel) => !panel)) return;
  function activate(index) {
    tabs.forEach((tab, i) => {
      tab.setAttribute('aria-selected', String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
      panels[i].hidden = i !== index;
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(index));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
        : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      activate(next);
      tabs[next].focus();
    });
  });
  activate(0);
}
bindTabs(['tab-register', 'tab-login'], ['register-form', 'login-form']);
bindTabs(['nav-main', 'nav-technical', 'nav-workflows'], ['page-main', 'page-technical', 'page-workflows']);

if (['#try', '#wall-title'].includes(location.hash)) document.getElementById('nav-technical')?.click();
