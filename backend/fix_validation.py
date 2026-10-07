import ast
import difflib
from security_scanner import scan_python_source

def validate_fix(original, fixed, finding, filename='source.py'):
    before=scan_python_source(original)
    try:
        ast.parse(fixed)
    except SyntaxError as exc:
        return {'syntax_valid':False,'error':str(exc),'changed':original!=fixed,'target_rule_cleared':False,'patch':''}
    after=scan_python_source(fixed)
    rule=finding.get('rule_id')
    before_count=sum(f.get('rule_id')==rule for f in before['issues'])
    after_count=sum(f.get('rule_id')==rule for f in after['issues'])
    return {'syntax_valid':True,'changed':original!=fixed,'target_rule_cleared':before_count>0 and after_count==0,'target_rule_before':before_count,'target_rule_after':after_count,'findings_before':len(before['issues']),'findings_after':len(after['issues']),'remaining_findings':after['issues'],'patch':''.join(difflib.unified_diff(original.splitlines(keepends=True),fixed.splitlines(keepends=True),fromfile='a/'+filename,tofile='b/'+filename)),'note':'Syntax and static rule checks only. Behavior and security are not guaranteed; no code or tests were executed.'}
