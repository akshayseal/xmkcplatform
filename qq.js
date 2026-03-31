const SUBJECTS = ['Current Affairs','Science & Nature','History & Geography','Arts, Culture & Sports'];
const SUBJECT_COLORS = {
  'Current Affairs':        '#534AB7',
  'Science & Nature':       '#185FA5',
  'History & Geography':    '#0F6E56',
  'Arts, Culture & Sports': '#854F0B',
};
const BANDS = [
  { min:85, name:'Knowledge Champion', color:'#085041', bg:'#E1F5EE', cls:'b-champ'   },
  { min:70, name:'Knowledge Expert',   color:'#0C447C', bg:'#E6F1FB', cls:'b-expert'  },
  { min:55, name:'Knowledge Builder',  color:'#633806', bg:'#FAEEDA', cls:'b-builder' },
  { min:40, name:'Knowledge Explorer', color:'#3C3489', bg:'#EEEDFE', cls:'b-explorer'},
  { min:0,  name:'Knowledge Seeker',   color:'#712B13', bg:'#FAECE7', cls:'b-seeker'  },
];

function getBand(qq) { return BANDS.find(b => qq >= b.min) || BANDS[BANDS.length-1]; }

function calcQQ(results, totalModulesInTerm) {
  if (!results || !results.length) return null;
  const subjectMap = {};
  for (const sub of SUBJECTS) {
    const subR = results.filter(r => r.subject === sub);
    if (subR.length) subjectMap[sub] = Math.round(subR.reduce((a,r)=>a+(r.score/r.max_score)*100,0)/subR.length);
  }
  const subVals = Object.values(subjectMap);
  if (!subVals.length) return null;
  const accuracy = Math.round(subVals.reduce((a,b)=>a+b,0)/subVals.length);
  const variance = subVals.reduce((s,x)=>s+(x-accuracy)**2,0)/subVals.length;
  const spread   = Math.round(Math.max(0, 100-Math.sqrt(variance)));
  const sorted   = [...results].sort((a,b)=>a.module_id-b.module_id);
  let improvement = 50;
  if (sorted.length >= 2) {
    const half = Math.ceil(sorted.length/2);
    const firstAvg = sorted.slice(0,half).reduce((a,r)=>a+(r.score/r.max_score)*100,0)/half;
    const lastAvg  = sorted.slice(half).reduce((a,r)=>a+(r.score/r.max_score)*100,0)/(sorted.length-half) || firstAvg;
    improvement = Math.round(Math.min(100, Math.max(0, 50+(lastAvg-firstAvg))));
  }
  const speedable = results.filter(r=>r.time_sec&&r.group_avg_sec&&(r.score/r.max_score)>=0.5);
  let speed = 50;
  if (speedable.length) {
    speed = Math.round(speedable.map(r=>{
      const ratio = r.time_sec/r.group_avg_sec;
      return ratio<=0.5?100:ratio>=2?0:Math.round(100-((ratio-0.5)/1.5)*100);
    }).reduce((a,b)=>a+b,0)/speedable.length);
  }
  const participation = Math.min(100, Math.round((results.length/totalModulesInTerm)*100));
  const qq = Math.round(accuracy*0.50+spread*0.15+improvement*0.15+speed*0.10+participation*0.10);
  return { qq, accuracy, spread, improvement, speed, participation, subjectScores: subjectMap,
           modulesCompleted: results.length, totalModules: totalModulesInTerm, band: getBand(qq) };
}

module.exports = { calcQQ, getBand, SUBJECTS, SUBJECT_COLORS, BANDS };
