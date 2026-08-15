import fs from "node:fs/promises";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const OUT = "D:/code/UoB/Anti_cheating/CS2_Anti_Cheat_Demo.pptx";
const BUILD = "D:/code/UoB/Anti_cheating/demo_deck_build";
const HERO = "D:/Software/FullyExternalCS2-main/assets/photo.png";

const C = {
  ink: "#101820", muted: "#56616F", pale: "#EDEDED", rule: "#B8BCC4",
  blue: "#3D8DFF", cyan: "#6DCBF4", light: "#DFF3FC", white: "#FFFFFF",
  red: "#D95D5D", green: "#2A9D78", amber: "#E6A23C", dark: "#0B1220"
};
const font = "Arial";

function addText(slide, text, x, y, w, h, size=22, opts={}) {
  const s = slide.shapes.add({ geometry: "textbox", name: opts.name,
    position: { left:x, top:y, width:w, height:h }, fill: "none",
    line: { style:"solid", fill:"none", width:0 } });
  s.text = text;
  s.text.style = { fontSize:size, typeface:font, color:opts.color||C.ink,
    bold:!!opts.bold, alignment:opts.align||"left", verticalAlignment:opts.valign||"top" };
  return s;
}

function box(slide, x,y,w,h, fill=C.pale, line=C.rule, radius="roundRect") {
  return slide.shapes.add({ geometry:radius, position:{left:x,top:y,width:w,height:h},
    fill, line:{style:"solid",fill:line,width:1}, borderRadius:"rounded-xl" });
}

function header(slide, title, n, kicker="CS2 ANTI-CHEAT RESEARCH") {
  addText(slide,kicker,54,34,620,28,16,{bold:true,color:C.blue});
  addText(slide,title,54,72,1130,58,48,{bold:true,name:`slide-${n}-title`});
  addText(slide,String(n).padStart(2,"0"),1180,674,48,22,14,{color:C.muted,align:"right"});
}

function bullet(slide, text, x,y,w, color=C.ink) {
  slide.shapes.add({ geometry:"ellipse", position:{left:x,top:y+9,width:10,height:10}, fill:C.blue,
    line:{style:"solid",fill:C.blue,width:0} });
  addText(slide,text,x+24,y,w-24,52,21,{color});
}

function note(slide, talk, sources=[]) {
  const src = sources.length ? `\n\n[Sources]\n${sources.map(s=>`- ${s}`).join("\n")}` : "\n\n[Sources]\n- Project source code and experiment artefacts in the local workspace.";
  slide.speakerNotes.textFrame.setText(talk + src);
  slide.speakerNotes.setVisible(true);
}

async function imageBytes(path) {
  const b=await fs.readFile(path); return b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength);
}

async function main() {
  await fs.mkdir(BUILD,{recursive:true});
  const p=Presentation.create({slideSize:{width:1280,height:720}});

  // 1 — Cover, based on Codex Grid slide 08's text/image split.
  {
    const s=p.slides.add(); s.background.fill=C.white;
    addText(s,"HOST-BASED DETECTION",54,42,520,28,16,{bold:true,color:C.blue});
    addText(s,"Detecting External\nCS2 Cheats",54,126,545,196,66,{bold:true,name:"cover-title"});
    addText(s,"A Windows process-handle monitoring prototype with risk-based classification",54,370,520,92,25,{color:C.muted});
    addText(s,"MSc Project Demonstration",54,596,450,30,20,{bold:true});
    s.images.add({blob:await imageBytes(HERO),contentType:"image/png",alt:"Controlled CS2 test showing an external overlay",fit:"cover",position:{left:654,top:42,width:572,height:584},geometry:"roundRect",borderRadius:"rounded-xl"});
    note(s,"Good afternoon. My project investigates how a host-based anti-cheat can detect an external CS2 program without relying on DLL injection evidence. I focus on a durable operating-system signal: another process holding powerful handles to the game. The prototype enumerates those handles, enriches the source identity, scores the risk, and records evidence for later review.",[
      "D:/Software/FullyExternalCS2-main/assets/photo.png — local test-program screenshot.",
      "D:/code/UoB/Anti_cheating/README.md — project scope."
    ]);
  }

  // 2 — Problem.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"External cheats leave no injected module to find",2);
    addText(s,"The detection gap",54,176,420,34,26,{bold:true});
    addText(s,"An external program runs in its own process. It can read game state and draw a transparent overlay while the game’s module list remains unchanged.",54,224,470,180,24,{color:C.muted});
    box(s,600,172,270,150,C.light,C.cyan);
    addText(s,"cs2.exe",630,204,210,38,30,{bold:true,align:"center"});
    addText(s,"game memory",630,256,210,30,20,{color:C.muted,align:"center"});
    box(s,930,172,270,150,"#F7E9E9",C.red);
    addText(s,"external process",960,204,210,38,28,{bold:true,align:"center"});
    addText(s,"overlay + input",960,282,210,26,20,{color:C.muted,align:"center"});
    s.shapes.add({geometry:"rightArrow",position:{left:870,top:220,width:54,height:48},fill:C.blue,line:{style:"solid",fill:C.blue,width:0}});
    addText(s,"process handle",792,286,220,28,17,{bold:true,color:C.blue,align:"center"});
    box(s,600,388,600,202,C.dark,C.dark);
    addText(s,"Research question",632,420,250,30,20,{bold:true,color:C.cyan});
    addText(s,"Can handle access distinguish a memory-reading test program from legitimate observers?",632,466,520,108,28,{bold:true,color:C.white});
    note(s,"The central problem is that an external cheat is not loaded into the CS2 process. A module scanner can therefore miss it. However, to read game memory it still needs a process handle with suitable access rights. That creates a host-visible relationship between the source process and cs2.exe, which becomes my primary detection surface.",[
      "D:/code/UoB/Anti_cheating/docs/FullyExternalCS2-static-analysis.md — static behaviour analysis."
    ]);
  }

  // 3 — Static analysis signals.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"Four host-visible signals",3);
    const items=[
      ["01","Memory access","ReadProcessMemory is used repeatedly against cs2.exe."],
      ["02","Process rights","The source holds VM_READ and other powerful rights."],
      ["03","Overlay window","A transparent external window renders ESP information."],
      ["04","Synthetic input","SendInput generates mouse movement and clicks."]
    ];
    items.forEach((it,i)=>{const col=i%2,row=Math.floor(i/2),x=54+col*594,y=166+row*220; box(s,x,y,550,178,i===0?C.light:C.pale,i===0?C.cyan:C.rule); addText(s,it[0],x+24,y+22,58,34,26,{bold:true,color:C.blue}); addText(s,it[1],x+94,y+20,410,38,28,{bold:true}); addText(s,it[2],x+94,y+72,410,72,21,{color:C.muted});});
    addText(s,"Prototype scope: implement and validate the process-handle signal first.",54,622,980,32,23,{bold:true,color:C.blue});
    note(s,"I first performed static analysis of the controlled test program. Four signals were visible from the host: cross-process memory reading, high process access rights, an overlay, and synthetic mouse input. I deliberately scoped the implemented prototype to handle monitoring because it is directly observable using Windows APIs and can be tested without modifying the game process.",[
      "D:/Software/FullyExternalCS2-main/Core/Kernel32.cs and Utils/Utility.cs — memory-read implementation.",
      "D:/Software/FullyExternalCS2-main/Graphics/OverlayRenderer.cs — overlay behaviour.",
      "D:/Software/FullyExternalCS2-main/Core/User32.cs — synthetic input API.",
      "D:/code/UoB/Anti_cheating/docs/FullyExternalCS2-static-analysis.md — analysis summary."
    ]);
  }

  // 4 — Architecture process.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"System handles become auditable evidence",4);
    const xs=[54,294,534,774,1014];
    for(let i=0;i<4;i++) s.shapes.add({geometry:"rightArrow",position:{left:xs[i]+180,top:300,width:76,height:42},fill:C.cyan,line:{style:"solid",fill:C.cyan,width:0}});
    const steps=[
      ["1","Enumerate","NtQuerySystemInformation"],
      ["2","Duplicate","inspect target PID"],
      ["3","Enrich","path, parent, hash, signature"],
      ["4","Score","rights + exceptions"],
      ["5","Record","snapshots, events, detections"]
    ];
    steps.forEach((it,i)=>{box(s,xs[i],222,186,204,i===4?C.dark:C.pale,i===4?C.dark:C.rule);addText(s,it[0],xs[i]+20,244,40,34,24,{bold:true,color:i===4?C.cyan:C.blue});addText(s,it[1],xs[i]+20,292,146,36,25,{bold:true,color:i===4?C.white:C.ink});addText(s,it[2],xs[i]+20,344,146,54,18,{color:i===4?"#D8E0EA":C.muted});});
    addText(s,"Read-only design",54,500,250,32,25,{bold:true,color:C.blue});
    addText(s,"The monitor duplicates handles for identification; it does not close handles or alter cs2.exe.",54,546,1040,48,23,{color:C.muted});
    note(s,"The implementation has five stages. It enumerates the extended system handle table, opens each source process, duplicates candidate handles, checks whether they resolve to the target CS2 PID, and enriches the source with identity data. The detection engine then scores the access mask and applies narrow contextual exceptions. Finally, CSV outputs preserve snapshots, lifecycle events, scan completeness, and detections. Importantly, this is a read-only monitor.",[
      "D:/code/UoB/Anti_cheating/CS2HandleMonitor/SystemHandleScanner.cs — enumeration and duplication.",
      "D:/code/UoB/Anti_cheating/CS2HandleMonitor/ProcessIdentityInspector.cs — identity enrichment.",
      "D:/code/UoB/Anti_cheating/CS2HandleMonitor/Program.cs — logging pipeline."
    ]);
  }

  // 5 — Risk model.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"Capabilities drive risk; context reduces noise",5);
    addText(s,"Access-right score",54,166,470,34,27,{bold:true});
    const rows=[["VM_READ","+40",C.blue],["VM_WRITE","+25",C.red],["VM_OPERATION","+20",C.amber],["CREATE_THREAD","+20",C.red],["Query-only access","5 total",C.muted]];
    rows.forEach((r,i)=>{const y=220+i*65; addText(s,r[0],66,y,300,30,22,{bold:i<4}); addText(s,r[1],390,y,110,30,24,{bold:true,color:r[2],align:"right"}); s.shapes.add({geometry:"rect",position:{left:66,top:y+40,width:434,height:2},fill:C.rule,line:{style:"solid",fill:C.rule,width:0}});});
    box(s,610,166,590,230,C.dark,C.dark);
    addText(s,"Default alert threshold",646,200,500,30,21,{bold:true,color:C.cyan});
    addText(s,"60",646,246,180,82,70,{bold:true,color:C.white});
    addText(s,"A full-access handle scores 100;\na query-only Steam handle scores 5.",820,250,330,72,24,{color:C.white});
    addText(s,"Contextual exception",610,430,400,32,25,{bold:true,color:C.blue});
    addText(s,"A dedicated-server conhost is reduced to risk 5 only when its parent PID and system path match the expected relationship.",610,478,570,100,22,{color:C.muted});
    note(s,"The first scoring model is intentionally interpretable. VM_READ contributes forty points, while write, operation, and thread-creation rights increase severity. A threshold of sixty separates the full-access test program from query-only observers. I also added a narrow exception for a dedicated-server console host, but only when both its parent relationship and trusted system path match. This shows why context matters alongside raw access rights.",[
      "D:/code/UoB/Anti_cheating/CS2HandleMonitor/ProcessAccessRights.cs — scoring weights.",
      "D:/code/UoB/Anti_cheating/CS2HandleMonitor/DetectionEngine.cs — thresholding and contextual exception."
    ]);
  }

  // 6 — Experiment and contribution boundary.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"Controlled tests clarify what I built",6);
    box(s,54,166,548,388,C.pale,C.rule);
    addText(s,"Experiment",84,196,240,34,27,{bold:true});
    bullet(s,"CS2 on de_dust2 with fixed test conditions",84,252,470);
    bullet(s,"2-second handle scans for about 10 minutes",84,322,470);
    bullet(s,"Compare CS2Cheat with Steam and console-host handles",84,392,470);
    bullet(s,"Preserve scan summaries and handle lifecycle events",84,462,470);
    box(s,650,166,550,388,C.dark,C.dark);
    addText(s,"Contribution boundary",682,196,380,34,27,{bold:true,color:C.cyan});
    addText(s,"Third-party test artefact",682,258,420,28,21,{bold:true,color:C.white});
    addText(s,"FullyExternalCS2 provides controlled external-cheat behaviour.",682,296,450,58,20,{color:"#D8E0EA"});
    addText(s,"Project implementation",682,384,420,28,21,{bold:true,color:C.white});
    addText(s,"Static analysis, baseline logger, handle scanner, identity enrichment, scoring and experiment logs.",682,422,450,88,20,{color:"#D8E0EA"});
    addText(s,"All claims in the demo are tied to source files or captured CSV data.",54,612,1080,34,23,{bold:true,color:C.blue});
    note(s,"For evaluation, I used FullyExternalCS2 as a third-party controlled test artefact; it is not presented as my implementation. My project work is the analysis, data collection, system-handle scanner, identity enrichment, detection logic, and experiment logging. The main comparison used approximately ten minutes of scans at two-second intervals, with Steam serving as a legitimate low-risk observer.",[
      "D:/Software/FullyExternalCS2-main/README.md — third-party test artefact attribution.",
      "D:/code/UoB/Anti_cheating/CS2BaselineLogger/Program.cs — baseline logger.",
      "D:/code/UoB/Anti_cheating/data/handle_monitor_20260808_222539 — controlled run data."
    ]);
  }

  // 7 — Results, based on Codex Grid chart evidence composition.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"High-risk in every scan",7);
    s.charts.add("bar",{position:{left:54,top:174,width:710,height:410},categories:["CS2Cheat","Steam"],series:[{name:"Risk score",values:[100,5],fill:C.blue,points:[{idx:0,fill:C.blue},{idx:1,fill:C.cyan}]}],barOptions:{direction:"column",grouping:"clustered",gapWidth:70},hasLegend:false,yAxis:{min:0,max:100,majorUnit:20,majorGridlines:{style:"solid",fill:"#D9DEE5",width:1},textStyle:{fill:C.muted,fontSize:15}},xAxis:{textStyle:{fill:C.ink,fontSize:18}},dataLabels:{showValue:true,position:"outEnd",textStyle:{fill:C.ink,fontSize:18,bold:true}},chartFill:C.white,plotAreaFill:C.white,chartLine:{style:"solid",fill:C.white,width:0},plotAreaLine:{style:"solid",fill:C.white,width:0}});
    box(s,818,174,382,116,C.dark,C.dark); addText(s,"301 / 301",846,196,326,44,36,{bold:true,color:C.white}); addText(s,"scans contained the high-risk handle",846,246,326,28,18,{color:"#D8E0EA"});
    box(s,818,316,382,116,C.light,C.cyan); addText(s,"100 vs 5",846,338,326,44,36,{bold:true,color:C.blue}); addText(s,"test program vs query-only Steam",846,388,326,28,18,{color:C.muted});
    box(s,818,458,382,142,C.pale,C.rule); addText(s,"Interpretation",846,480,300,28,22,{bold:true}); addText(s,"Access capability separated these two observed processes in this run.",846,520,310,68,19,{color:C.muted});
    addText(s,"Observed risk score (higher means more powerful process access)",54,610,710,28,18,{color:C.muted});
    note(s,"In the controlled run, the test program and Steam were both visible in every one of the 301 scans. The test program held a full-access handle and scored one hundred. Steam held only query and synchronisation rights and scored five. At the threshold of sixty, the test program was consistently high-risk while Steam remained low-risk. This supports feasibility, but it is not yet a population-level false-positive result.",[
      "D:/code/UoB/Anti_cheating/data/handle_monitor_20260808_222539/scan_summary.csv — 301 scans and one high-risk handle per scan.",
      "D:/code/UoB/Anti_cheating/data/handle_monitor_20260808_222539/handles.csv — observed access rights and risk scores."
    ]);
  }

  // 8 — Conclusion.
  {
    const s=p.slides.add(); s.background.fill=C.white; header(s,"Handle monitoring is a signal—not a verdict",8);
    addText(s,"What the prototype demonstrates",54,166,500,34,27,{bold:true});
    bullet(s,"External memory readers remain visible through OS handle relationships.",54,224,520);
    bullet(s,"Interpretable scoring separates full access from query-only access in the test run.",54,304,520);
    bullet(s,"Identity and lifecycle logs make alerts auditable.",54,384,520);
    box(s,650,166,550,388,C.dark,C.dark);
    addText(s,"Next steps",682,198,300,34,27,{bold:true,color:C.cyan});
    const next=["Validate against overlays, capture tools and accessibility software","Add window, input and network telemetry","Calibrate thresholds with larger labelled datasets","Investigate kernel-level visibility and handle evasion"];
    next.forEach((t,i)=>{addText(s,String(i+1).padStart(2,"0"),682,258+i*66,44,28,20,{bold:true,color:C.cyan});addText(s,t,744,256+i*66,404,48,20,{color:C.white});});
    addText(s,"Conclusion: combine multiple signals before enforcement.",54,612,1040,34,25,{bold:true,color:C.blue});
    note(s,"To conclude, process-handle monitoring provides a strong, explainable signal for this class of external cheat. The prototype consistently separated the controlled memory reader from a query-only Steam handle and preserved evidence for review. However, a handle is a risk signal rather than proof of cheating. The next stage is broader benign-software testing, multi-signal correlation, and stronger visibility against evasion. Therefore, enforcement should be based on combined evidence rather than this score alone.",[
      "D:/code/UoB/Anti_cheating/README.md — documented limitations and proposed signal combination.",
      "D:/code/UoB/Anti_cheating/docs/FullyExternalCS2-static-analysis.md — limitations and recommended extensions."
    ]);
  }

  for (const [i,s] of p.slides.items.entries()) {
    const png=await p.export({slide:s,format:"png",scale:1});
    await fs.writeFile(`${BUILD}/slide-${i+1}.png`,new Uint8Array(await png.arrayBuffer()));
    const layout=await s.export({format:"layout"}); await fs.writeFile(`${BUILD}/slide-${i+1}.layout.json`,await layout.text());
  }
  const montage=await p.export({format:"png",montage:true,scale:1}); await fs.writeFile(`${BUILD}/montage.png`,new Uint8Array(await montage.arrayBuffer()));
  const deck=await PresentationFile.exportPptx(p); await deck.save(OUT);
}

main().catch(e=>{console.error(e);process.exitCode=1;});
