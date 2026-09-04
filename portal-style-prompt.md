# Prompt de estilo para nuevo portal

Usa este documento como instruccion base para crear un nuevo proyecto manteniendo el estilo visual y de interaccion del portal SGSI ENS actual.

## Prompt listo para Codex

Quiero desarrollar un nuevo portal administrativo manteniendo el estilo visual, la densidad y los patrones de interfaz del proyecto SGSI ENS de referencia. Construye una aplicacion tipo backoffice profesional, sobria y orientada a gestion operativa, no una landing page.

Mantén estas reglas de estilo:

- Usa React con TypeScript y Tailwind CSS si el stack no esta fijado.
- La app debe ocupar toda la pantalla: contenedor raiz `h-screen w-full bg-slate-50 text-slate-900 font-sans overflow-hidden`.
- En desktop usa un sidebar fijo a la izquierda de `w-64`, fondo azul marino casi negro `#0b1329`, texto `slate-100`, borde derecho `#1e293b`, sticky `top-0`, altura completa.
- El contenido principal debe estar en un panel `flex-1 flex flex-col bg-slate-50 overflow-hidden`, con scroll interno y padding `p-6 md:p-8`.
- En mobile sustituye el sidebar por un header blanco sticky con logo/titulo y una barra horizontal de navegacion con scroll.
- La navegacion se organiza por secciones en mayusculas pequenas: dashboards, inventarios, gestion, cumplimiento, administracion, etc.
- Usa iconos de `lucide-react` en navegacion, botones y estados. No dibujes iconos manualmente si existe un icono lucide adecuado.
- El item activo del sidebar usa `bg-[#1c2c54]/60 text-blue-400 font-bold`; los items inactivos usan `text-slate-400` y hover `hover:bg-[#1c2c54]/20 hover:text-slate-200`.
- El area de trabajo usa cabeceras de seccion blancas con borde `border-slate-200`, sombra suave `shadow-sm`, sin radio o con radio minimo, y una barra izquierda azul `border-l-4 border-l-blue-600`.
- Las pantallas deben sentirse densas y funcionales: tablas, filtros, KPIs, formularios, estados y acciones claras. Evita composiciones de marketing, heroes grandes, gradientes decorativos, orbes o tarjetas anidadas.
- Usa tarjetas solo para piezas repetidas, KPIs, modales o paneles funcionales. No metas cards dentro de cards.
- Predomina una paleta neutral: `slate` para estructura/texto/fondos, `blue-600` como accion primaria, `slate-900` para acciones secundarias fuertes, y colores semanticos para estados: `emerald`, `amber`, `red`, `rose`, `violet`, `indigo`.
- Boton primario: `bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold` o `text-xs font-bold uppercase tracking-wider` en acciones compactas.
- Boton secundario: `bg-white border border-slate-300 text-slate-700 hover:bg-slate-50`.
- Boton oscuro para informes/exportaciones: `bg-slate-900 hover:bg-slate-800 text-white`.
- Mantén botones y controles con `rounded-none` o radio muy bajo, salvo login/autenticacion donde se permite `rounded-lg` o `rounded-2xl`.
- Inputs/selects/textareas: borde `border-slate-300` o `border-gray-300`, fondo blanco, texto pequeno, foco `focus:outline-none focus:border-blue-500`, sin efectos llamativos.
- Tablas: contenedor `bg-white border border-slate-200 shadow-sm overflow-x-auto`; cabecera `bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider`; filas con `divide-y divide-slate-200`, hover `hover:bg-slate-50/50`; usar `min-w-[...]` para tablas densas.
- KPIs: cajas `bg-slate-50 p-4 border border-slate-200 flex items-center gap`, icono en bloque coloreado claro, etiqueta `text-[10px] font-bold uppercase text-slate-500 tracking-wider`, valor `text-2xl font-extrabold text-slate-800`.
- Modales: overlay `fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs p-4 overflow-y-auto`; panel blanco con `border border-slate-200`, `shadow-xl`, max width adecuado, y si es editor importante usar `border-l-4 border-l-blue-600`.
- Mensajes de estado: error `bg-red-50 text-red-800 border-red-100` con icono; exito `bg-emerald-50 text-emerald-800 border-emerald-100`; avisos con `amber`.
- Tipografia: sistema sans (`ui-sans-serif, system-ui, sans-serif`). Titulos de pantalla `text-xl font-bold text-slate-900 tracking-tight`; subtitulos `text-sm text-slate-500`; etiquetas de formulario `text-xs font-bold uppercase text-slate-600`.
- Mantén textos en espanol formal, orientados a gestion: "Nuevo", "Editar", "Eliminar", "Guardar", "Informe PDF", "Exportar", "Gestionar", "Mostrando X de Y".
- Respeta accesibilidad basica: botones reales, labels, `aria-label` en botones solo-icono, modales con `role="dialog"` y `aria-modal="true"`.
- Evita que el texto se solape o cambie el layout: usa `truncate`, `whitespace-nowrap`, `min-w`, `max-w`, grids responsivos y scroll horizontal en tablas.

Cuando implementes pantallas nuevas, sigue este esqueleto visual:

```tsx
<div className="space-y-6">
  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white p-6 rounded-none border border-slate-200 border-l-4 border-l-blue-600 shadow-sm gap-4">
    <div>
      <h2 className="text-xl font-bold text-slate-900 tracking-tight">Titulo del modulo</h2>
      <p className="text-sm text-slate-500 mt-0.5">Descripcion breve y operativa del modulo.</p>
    </div>
    <div className="flex flex-wrap items-center gap-2">
      <button className="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-none text-sm font-semibold shadow-sm">
        Accion principal
      </button>
    </div>
  </div>

  <div className="bg-white p-5 border border-slate-200 shadow-sm flex flex-col sm:flex-row sm:items-center gap-4">
    {/* filtros, busqueda, contador de resultados */}
  </div>

  <div className="bg-white border border-slate-200 shadow-sm overflow-x-auto">
    <table className="w-full text-left border-collapse min-w-[1000px]">
      <thead>
        <tr className="bg-slate-50 border-b border-slate-200 text-xs font-bold uppercase text-slate-500 tracking-wider">
          {/* columnas */}
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-200 text-sm">
        {/* filas */}
      </tbody>
    </table>
  </div>
</div>
```

## Guia resumida del estilo

### Personalidad visual

Portal administrativo serio, denso y utilitario. Debe parecer una herramienta interna de gobierno, cumplimiento, inventario o gestion, con informacion escaneable y controles predecibles.

No debe parecer una pagina comercial. Evita heroes, ilustraciones decorativas, cards flotantes innecesarias, fondos con gradientes ornamentales y grandes espacios vacios.

### Layout

- Desktop: sidebar oscuro izquierdo + panel principal claro.
- Mobile: header blanco sticky + navegacion horizontal con scroll.
- El scroll principal vive dentro del panel de contenido, no en toda la pagina.
- Las pantallas internas usan `space-y-6`.
- Las secciones empiezan con una cabecera blanca funcional con titulo, descripcion y acciones.

### Color

- Fondo app: `slate-50`.
- Texto principal: `slate-900`.
- Texto secundario: `slate-500` / `slate-600`.
- Sidebar: `#0b1329`.
- Sidebar activo/submenus: `#1c2c54` + `blue-400`.
- Accion primaria: `blue-600`.
- Accion fuerte secundaria: `slate-900`.
- Bordes: `slate-200` / `slate-300`.
- Estados: `emerald` para exito/implementado, `amber` para en proceso, `red`/`rose` para error o riesgo, `slate` para neutro/excluido.

### Componentes

- Botones con icono + texto para acciones importantes.
- Botones solo-icono para acciones repetidas de fila: editar, eliminar, cerrar, ordenar.
- Tablas densas con cabeceras pequenas en uppercase.
- KPIs compactos con icono, etiqueta pequena, valor grande y nota secundaria.
- Formularios en modales o paneles blancos, con labels uppercase pequenas.
- Badges compactos con fondo claro, borde y texto en negrita.

### Detalles a preservar

- Uso frecuente de `rounded-none`.
- Sombra suave: `shadow-sm` para paneles, `shadow-xl` para modales.
- Borde izquierdo azul en cabeceras o editores importantes.
- Texto de labels y cabeceras en uppercase pequeno con tracking.
- Iconografia consistente con `lucide-react`.
- Densidad alta sin perder legibilidad.
