# coap_server.py
import asyncio
from aiocoap import resource, Context, Message, Code

class MyResource(resource.Resource):
    async def render_post(self, request):
        payload = request.payload.decode()
        print(f"[Server] Received POST: {payload}")
        return Message(code=Code.CHANGED, payload=b"Data received")

async def main():
    root = resource.Site()
    root.add_resource(['iot-data'], MyResource())

    # Bind to the Wi-Fi IP of this system
    await Context.create_server_context(root, bind=('10.182.3.163', 5683))
    print("[Server] CoAP server running on 10.182.3.163:5683")
    await asyncio.get_running_loop().create_future()  # Run forever

if __name__ == '__main__':
    asyncio.run(main())
