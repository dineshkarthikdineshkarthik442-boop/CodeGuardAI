import os
from fastapi.responses import JSONResponse
COOKIE='cg_session'

def auth_response(result,error=None):
    if not result:return JSONResponse({'success':False,'error':error or 'Authentication failed.'})
    response=JSONResponse({'success':True,'user':result['user'],'token':'cookie-session'})
    response.set_cookie(COOKIE,result['token'],httponly=True,secure=os.getenv('CODEGUARD_COOKIE_SECURE','0')=='1',samesite='lax',max_age=86400,path='/')
    return response
