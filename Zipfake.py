import os
import sys

def title():
    print("""  ______                   _     __             ____  ____    
.' ____ \                 (_)   /  |           |_   ||   _|   
| (___ \_|  _ .--..--.    __    `| |    .---.    | |__| |     
 _.____`.  [ `.-. .-. |  [  |    | |   / /__\\\\    |  __  |     
| \____) |  | | | | | |   | |   _| |_  | \__., _| |  | |_    
 \______.' [___||__||__] [___] |_____|  '.__.' |____||____|         
                                            ——Zipfake Tool V1.0\n""")
    print("此脚本针对CTF中zip伪加密，支持检测是否存在伪加密并自动将除伪后的文件写入新文件")

# 将文件转换为16进制编码方便后面读取
def get_zip_hex(zip_filename):
    try:
        with open(zip_filename, 'rb') as file:
            binary_content = file.read()
            hex_content = binary_content.hex()
            return hex_content
    except FileNotFoundError:
        print(f"未找到文件：{zip_filename}")
        return None
    except PermissionError:
        print("无法读取文件（无权限访问）")
        return None

# 对文件中的标志位进行搜索，以及基础的判断
def find_zip_hex(zip_hex):
    # 将文件简单分割处理
    t = False
    n = 0
    sit = []    # 记录字节位置
    zip_hex_split = zip_hex.split("504b")
    for i in range (len(zip_hex_split)):
        if zip_hex_split[i][:4] == "0304":
            if int(zip_hex_split[i][9]) % 2 != 0 :
                print("可能为真加密，可以尝试破解")
                t = True
            else:
                n += len(zip_hex_split[i]) + 4
                continue
        if zip_hex_split[i][:4] == "0102":
            if int(zip_hex_split[i][13]) % 2 != 0:
                sit.append(int(n+13))
                print(f"[+]该文件可能为伪加密，存疑字节为：{n+13}")
        n += len(zip_hex_split[i]) + 4
    return sit , t

# 对可可疑文件处理输出
def zip_solve(hex_string,sit,t):
    try:
        with open("flag.zip","wb") as f:
            write = list(hex_string)
            if t:
                write[13] = "0"
            for i in sit:
                write[i] = "0"
            write = "".join(write)
            write = bytes.fromhex(write)
            f.write(write)
        parent_directory_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        print(f"[+]文件成功写入，写入位置为:{parent_directory_path}\\flag.zip")
    except Exception as e:
        print(f"文件并没有被写入，发生错误为：{e}")

if __name__ == "__main__":
    title()
    str13 = input("输入待检测的文件位置\n >>> ")
    try:
        hex_string = get_zip_hex(str13)
        sit , t =find_zip_hex(hex_string)
        if int(input("\n是否需要进一步的除伪(1 继续 / 0 结束)\n >>> ")) or not t :
            zip_solve(hex_string, sit, t)
    except KeyboardInterrupt:
        print("Ctrl + C 手动终止了进程")
        sys.exit()
    except BaseException as e:
        err = str(e)
        print('脚本详细报错：' + err)
        sys.exit(0)