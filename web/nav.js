// Site navigation: one dropdown open at a time; close on outside click or Escape.
const menus = [...document.querySelectorAll('.site-nav details.menu')];
for (const menu of menus) {
  menu.addEventListener('toggle', () => {
    if (menu.open) menus.filter((m) => m !== menu).forEach((m) => { m.open = false; });
  });
}
document.addEventListener('click', (event) => {
  if (!event.target.closest('.site-nav')) menus.forEach((m) => { m.open = false; });
});
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  const open = menus.find((m) => m.open);
  if (open) { open.open = false; open.querySelector('summary').focus(); }
});
