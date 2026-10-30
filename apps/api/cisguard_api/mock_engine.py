from fastapi import FastAPI
app = FastAPI(title='Development device-engine placeholder')


@app.get('/health')
def health():
    return {'status':'ok','capabilities':[],'device_operations':'UNSUPPORTED'}
