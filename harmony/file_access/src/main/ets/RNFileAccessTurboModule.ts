/**
 * Copyright (c) 2015 Kyle Corbitt

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { TurboModule } from '@rnoh/react-native-openharmony/ts';
import { TM } from '@rnoh/react-native-openharmony/generated/ts';
import { TurboModuleContext } from '@rnoh/react-native-openharmony/ts';
import fs, { ReadTextOptions } from '@ohos.file.fs';
import hash from '@ohos.file.hash';
import http from '@ohos.net.http';
import HashMap from '@ohos.util.HashMap';
import { BusinessError } from '@ohos.base';
import buffer from '@ohos.buffer';
import statvfs from "@ohos.file.statvfs";
import zlib from '@ohos.zlib';
import util from '@ohos.util';
import resourceManager from '@ohos.resourceManager';
import { Context } from '@ohos.abilityAccessCtrl';
import emitter from '@ohos.events.emitter';
import Logger from './Logger';

export class RNFileAccessTurboModule extends TurboModule implements TM.FileAccess.Spec {
  private context: Context;
  private resourceManager: resourceManager.ResourceManager;
  private activeRequests: Map<string, number> = new Map();

  // 将资源文件内容转为base64编码
  private parsingRawFile(rawFile: Uint8Array): string {
    let base64 = new util.Base64Helper();
    let result = base64.encodeToStringSync(rawFile);
    return result;
  }

  constructor(ctx: TurboModuleContext) {
    super(ctx);
    this.context = this.ctx.uiAbilityContext;
    this.resourceManager = this.context.resourceManager;
  }

  // 常量
  getConstants(): {
    CacheDir: string;
    DatabaseDir?: string | undefined;
    DocumentDir: string;
    LibraryDir?: string | undefined;
    MainBundleDir: string;
    SDCardDir?: string | undefined;
  } {
    let applicationContext = this.context.getApplicationContext();
    let result = {
      // 沙箱路径
      FileSandBoxPath: this.context.filesDir,
      // 缓存路径
      FileCachePath: this.context.cacheDir,
      MainBundlePath: applicationContext.bundleCodeDir,
      TemporaryDirectoryPath: applicationContext.tempDir,
      LibraryDirectoryPath: applicationContext.preferencesDir,
      DatabaseDir: applicationContext.databaseDir,
      BundleCodeDir: this.context.distributedFilesDir,
      // 文件
      RNFSFileTypeRegular: 0,
      // 文件夹
      RNFSFileTypeDirectory: 1,
    }
    return {
      CacheDir: result.FileCachePath,
      DatabaseDir: result.DatabaseDir,
      DocumentDir: result.FileSandBoxPath,
      LibraryDir: result.LibraryDirectoryPath,
      MainBundleDir: result.MainBundlePath,
      SDCardDir: result.BundleCodeDir
    }
  }

  // 将内容写入文件
  writeFile(path: string, data: string, encoding: string): Promise<void> {
    return new Promise((resolve, reject) => {
      // 判断data是否符合base64格式编码
      let isBase64 =
        (data) => /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/.test(data) &&
          (data.length % 4 === 0);
      if (encoding.toLowerCase() == 'base64' && !isBase64(data)) {
        return reject(`Failed to write to ${path}, invalid base64.`);
      }
      let result;
      switch (encoding.toLowerCase()) {
        case "base64":
          result = buffer.from(data, 'base64').toString('utf8');
          break;
        case "utf8":
          result = data;
          break;
        default:
          result = data;
          break;
      }
      let file = fs.openSync(path, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE | fs.OpenMode.TRUNC);
      fs.write(file.fd, result, (err: BusinessError) => {
        if (err) {
          reject('Directory could not be created');
        } else {
          resolve();
        }
        fs.closeSync(file);
      });
    })
  }

  // 读取文件的内容
  readFile(path: string, encoding: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let file = fs.openSync(path, fs.OpenMode.READ_WRITE);
      let arrayBuffer = new ArrayBuffer(4096);
      fs.read(file.fd, arrayBuffer, (err: BusinessError, readLen: number) => {
        if (err) {
          reject("read failed with error message: " + err.message + ", error code: " + err.code);
        } else {
          let buf = buffer.from(arrayBuffer, 0, readLen);
          switch (encoding.toLowerCase()) {
            case "base64":
              resolve(buf.toString('base64'));
              break;
            case "utf8":
              resolve(buf.toString('utf8'));
              break;
            default:
              resolve(buf.toString('utf8'));
              break;
          }
        }
        fs.closeSync(file);
      });
    })
  }

  // 删除文件
  unlink(path: string): Promise<void> {
    return new Promise((resolve, reject) => {
      fs.rmdir(path, (err: BusinessError) => {
        if (err) {
          reject('FilePath does not exist');
        } else {
          resolve();
        }
      });
    })
  }

  // 对文件内容进行哈希处理
  hash(path: string, algorithm: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let algorithms: HashMap<string, string> = new HashMap();
      algorithms.set('MD5', 'md5');
      algorithms.set('SHA-1', 'sha1');
      algorithms.set('SHA-224', 'sha224');
      algorithms.set('SHA-256', 'sha256');
      algorithms.set('SHA-384', 'sha384');
      algorithms.set('SHA-512', 'sha512');
      // algorithm不存在
      if (!algorithms.hasKey(algorithm)) {
        reject('Invalid hash algorithm');
        return;
      }
      // 判断是否是文件夹
      let isDirectory = fs.statSync(path).isDirectory();
      if (isDirectory) {
        reject('file  IsDirectory');
        return;
      }
      // 判断文件是否在
      let res = fs.accessSync(path);
      if (!res) {
        reject('file not exists');
        return;
      }
      hash.hash(path, algorithms.get(algorithm), (err: BusinessError, result: string) => {
        if (err) {
          reject("calculate file hash failed with error message: " + err.message + ", error code: " + err.code);
        } else {
          resolve(result.toLocaleLowerCase());
        }
      })
    })
  }

  // 创建一个新目录，返回创建目录的路径
  mkdir(path: string): Promise<string> {
    return new Promise(async (resolve, reject) => {
      fs.mkdir(path, true, (err: BusinessError) => {
        if (err) {
          if (err.code == 13900015) {
            // 文件夹存在
            resolve(path);
          } else {
            reject(`Directory could not be created ${err.message} ${err.code}`);
          }
        } else {
          resolve(path);
        }
      })
    })
  }

  // 移动文件内容
  mv(source: string, target: string): Promise<void> {
    return new Promise((resolve, reject) => {
      fs.moveFile(source, target, 0, (err) => {
        if (err) {
          reject("move file failed with error message: " + err.message + ", error code: " + err.code);
        } else {
          resolve();
        }
      });
    })
  }

  // 读取文件元数据
  stat(path: string): Promise<TM.FileAccess.FileStat> {
    return new Promise((resolve, reject) => {
      let statResult: TM.FileAccess.FileStat = {
        'filename': '',
        'path': '',
        'type': '',
        'size': 0,
        'lastModified': -1
      };
      // 判断文件是否在
      let res = fs.accessSync(path);
      if (!res) {
        reject('file not exists');
        return;
      }
      fs.stat(path, (err: BusinessError, stat: fs.Stat) => {
        let filename = path.split('/').pop();
        if (err) {
          reject(`error message: ` + err.message + ', error code: ' + err.code);
        } else {
          statResult.filename = filename;
          statResult.path = path;
          statResult.size = stat.size;
          statResult.lastModified = stat.mtime;
          statResult.type = stat.isDirectory() ? 'directory' : 'file';
          resolve(statResult);
        }
      });
    })
  }

  // 判断文件是否存在
  exists(path: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      fs.access(path, (err: BusinessError, result: boolean) => {
        if (err) {
          reject('File does not exist');
        } else {
          resolve(result);
        }
      });
    })
  }

  // 复制文件
  cp(source: string, target: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        if (fs.accessSync(source)) {
          if (fs.accessSync(target)) {
            reject(`Failed to copy '${source}' to '${target}', because an item with the same name already exists.`);
            return;
          } else {
            let targetFile = fs.openSync(target, fs.OpenMode.CREATE);
            fs.closeSync(targetFile);
          }
          fs.copyFileSync(source, target);
          resolve();
        } else {
          reject('原文件不存在');
        }
      } catch (err) {
        reject('复制失败');
      }
    })
  }

  // 检查路径是否是目录
  isDir(path: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      let isExists = fs.accessSync(path);
      if (!isExists) {
        resolve(false);
      }
      let isDirectory = fs.statSync(path).isDirectory();
      if (!isDirectory) {
        resolve(false);
      } else {
        resolve(true);
      }
    })
  }

  // 列出目录中的文件
  ls(path: string): Promise<string[]> {
    return new Promise((resolve, reject) => {
      let isDirectory = fs.statSync(path).isDirectory();
      if (!isDirectory) {
        reject("目录不存在");
      }
      let create = fs.accessSync(path);
      if (!create) {
        reject("文件不存在");
      }
      let filenames = fs.listFileSync(path);
      resolve(filenames);
    })
  }

  // 检查设备可用空间
  df(): Promise<TM.FileAccess.FsStat> {
    return new Promise((resolve) => {
      let totalSize = statvfs.getTotalSizeSync(this.context.filesDir);
      let freeSize = statvfs.getFreeSizeSync(this.context.filesDir);
      let df: TM.FileAccess.FsStat = {
        internal_free: freeSize,
        internal_total: totalSize,
      };
      resolve(df);
    })
  }

  // 解压
  unzip(source: string, target: string): Promise<void> {
    return new Promise((resolve) => {
      let options: zlib.Options = {
        level: zlib.CompressLevel.COMPRESS_LEVEL_DEFAULT_COMPRESSION
      };
      try {
        zlib.decompressFile(source, target, options).then((data: void) => {
          Logger.info('decompressFile success.data: ' + JSON.stringify(data));
          resolve();
        }).catch((errData: BusinessError) => {
          Logger.error(`errData is errCode:${errData.code}  message:${errData.message}`);
        })
      } catch (errData) {
        let code = (errData as BusinessError).code;
        let message = (errData as BusinessError).message;
        Logger.error(`errData is errCode:${code}  message:${message}`);
      }
    })
  }

  // 读取目录中所有文件的元数据
  statDir(path: string): Promise<TM.FileAccess.FileStat[]> {
    return new Promise((resolve, reject) => {
      // 判断是否是目录
      let isDirectory = fs.statSync(path).isDirectory();
      if (!isDirectory) {
        reject("目录不存在");
      }
      // 判断文件是否在
      let res = fs.accessSync(path);
      if (!res) {
        reject('file not exists');
        return;
      }
      // 获取目录下的文件名称
      let filenames = fs.listFileSync(path);
      if (filenames.length > 0) {
        // 遍历获取文件信息
        let statList = filenames.map((item) => {
          let stat = fs.statSync(path + "/" + item);
          if (stat) {
            return {
              filename: item,
              path: path + "/" + item,
              type: stat.isDirectory() ? 'directory' : 'file',
              size: stat.size,
              lastModified: stat.mtime,
            }
          }
        })
        resolve(statList);
      } else {
        reject('目录下没有文件');
      }
    })
  }

  // 读取文件的一大块内容，从位于的字节开始offset，读取length字节
  readFileChunk(path: string, offset: number, length: number, encoding: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let readTextOption: ReadTextOptions = {
        offset: offset,
        length: length,
        encoding: 'utf-8'
      };
      fs.readText(path, readTextOption, (err: BusinessError, str: string) => {
        if (err) {
          reject('readText failed with error message: ' + err.message + ', error code: ' + err.code);
        } else {
          let result;
          switch (encoding.toLowerCase()) {
            case "base64":
              result = buffer.from(str, 'utf8').toString('base64');
              break;
            case "utf8":
              result = str.toString();
              break;
            default:
              result = str.toString();
              break;
          }
          resolve(result);
        }
      });
    })
  }

  // 将内容附加到文件
  appendFile(path: string, data: string, encoding: string): Promise<void> {
    return new Promise((resolve, reject) => {
      // 判断data是否符合base64格式编码
      let isBase64 =
        (data) => /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/.test(data) &&
          (data.length % 4 === 0);
      if (encoding.toLowerCase() == 'base64' && !isBase64(data)) {
        return reject(`Failed to write to ${path}, invalid base64.`);
      }
      let result;
      switch (encoding.toLowerCase()) {
        case "base64":
          result = buffer.from(data, 'base64').toString('utf8');
          break;
        case "utf8":
          result = data;
          break;
        default:
          result = data;
          break;
      }
      // 读写创建 文件内容追加到末尾
      let file = fs.openSync(path, fs.OpenMode.READ_WRITE | fs.OpenMode.APPEND);
      fs.write(file.fd, result, (err: BusinessError) => {
        if (err) {
          reject('Directory could not be created');
        } else {
          resolve();
        }
        fs.closeSync(file);
      });
    })
  }

  // 将一个文件附加到另一个文件。返回写入的字节数
  concatFiles(source: string, target: string): Promise<number> {
    return new Promise((resolve) => {
      // 源文件字节长度
      let sourceLen;
      // 判断源文件是否存在
      let sourceRes = fs.accessSync(source);
      if (!sourceRes) {
        sourceLen = 0;
      } else {
        // 读取源文件字节长度
        let sourceFile = fs.openSync(source, fs.OpenMode.READ_WRITE);
        let sourceBuf = new ArrayBuffer(4096);
        sourceLen = fs.readSync(sourceFile.fd, sourceBuf);
        let sourceInfo = buffer.from(sourceBuf, 0, sourceLen).toString();
        fs.closeSync(sourceFile);

        // 将内容写入文件
        let targetFile = fs.openSync(target, fs.OpenMode.READ_WRITE | fs.OpenMode.APPEND);
        fs.writeSync(targetFile.fd, sourceInfo);
        fs.closeSync(targetFile);
      }
      resolve(sourceLen);
    })
  }

  // 将网络请求保存到文件
  fetch(requestId: number, resource: string, init: {
    body?: string | undefined;
    headers?: Object | undefined;
    method?: string | undefined;
    network?: string | undefined;
    path?: string | undefined;
  }): void {
    try {
      let fd = fs.openSync(init.path, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE).fd;
      let httpRequest = http.createHttp();
      const methodMap = {
        OPTIONS: http.RequestMethod.OPTIONS,
        GET: http.RequestMethod.GET,
        HEAD: http.RequestMethod.HEAD,
        POST: http.RequestMethod.POST,
        PUT: http.RequestMethod.PUT,
        DELETE: http.RequestMethod.DELETE,
        TRACE: http.RequestMethod.TRACE,
        CONNECT: http.RequestMethod.CONNECT,
      };
      // 请求方法
      const methods = methodMap[init?.method?.toUpperCase()] || http.RequestMethod.GET;
      // 订阅事件
      emitter.emit('requestId' + requestId);
      // 存储requestId
      this.activeRequests.set("requestId", requestId);
      // 用于订阅HTTP响应头，此接口会比request请求先返回。可以根据业务需要订阅此消息
      httpRequest.on("headersReceive", (header: Object) => {
        Logger.info("header: " + JSON.stringify(header));
      });
      // 发起请求
      httpRequest.requestInStream(resource,
        { method: methods, header: init?.headers }, (err: BusinessError, code: number) => {
          if (!err) {
            Logger.info('requestInStream is ok', code.toString());
          } else {
            err && Logger.error('requestInStream error', JSON.stringify(err));
          }
        });
      httpRequest.on("dataReceive", (data: ArrayBuffer) => {
        fs.writeSync(fd, data);
      });
      httpRequest.on("dataEnd", () => {
        fs.closeSync(fd);
      })
    } catch (err) {
      Logger.error(err);
    }
  };

  // 从应用的资源包中复制指定的资源文件到目标位置
  cpAsset(asset: string, target: string, type: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.resourceManager.getRawFileContent(asset, (err: BusinessError, value: Uint8Array) => {
        if (err) {
          reject(err.message);
        } else {
          if (fs.accessSync(target)) {
            return reject(`Failed to copy '${asset}' to '${target}', because an item with the same name already exists.`);
          } else {
            let file = fs.openSync(target, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE | fs.OpenMode.TRUNC);
            fs.write(file.fd, this.parsingRawFile(value), (err: BusinessError) => {
              if (err) {
                reject('Directory could not be created');
              } else {
                resolve();
              }
              fs.closeSync(file);
            })
          }
        }
      }
      )
    })
  }

  // 将文件复制到外部控制的位置
  cpExternal(source: string, targetName: string, dir: string): Promise<void> {
    return new Promise((resolve, reject) => {
      // 判断待复制文件是否存在
      let isSource = fs.accessSync(source);
      if (!isSource) {
        reject('原文件不存在');
        return;
      }
      let targetFolder;
      switch (dir) {
        case 'audio':
          targetFolder = this.context.cacheDir + '/Music';
          break;
        case 'downloads':
          targetFolder = this.context.cacheDir + '/Downloads';
          break;
        case 'images':
          targetFolder = this.context.cacheDir + '/Pictures';
          break;
        case 'video':
          targetFolder = this.context.cacheDir + '/Movies';
          break;
      }
      // 复制后的文件路径
      let filePath = `${targetFolder}/${targetName}`;
      // 如果文件夹不存在就创建文件夹
      if (!fs.accessSync(targetFolder.toString())) {
        fs.mkdirSync(targetFolder.toString(), true);
      }
      // 判断复制后的文件名是否存在
      if (fs.accessSync(filePath)) {
        reject(`Failed to copy '${source}' to '${filePath}', because an item with the same name already exists.`);
        return;
      }
      // 复制文件
      fs.copyFile(source, filePath, (err: BusinessError) => {
        if (err) {
          reject("copy file failed with error message: " + err.message + ", error code: " + err.code);
          return;
        } else {
          resolve();
        }
      });
    })
  }

  // 取消网络请求
  cancelFetch(requestId: number): Promise<void> {
    return new Promise((resolve) => {
      // 事件处理函数
      const eventListener = () => {
        let httpRequest = http.createHttp();
        httpRequest.off("headersReceive");
        httpRequest.destroy();
        resolve();
      };
      if (requestId === this.activeRequests.get('requestId')) {
        emitter.once('requestId' + requestId, eventListener);
      }
      return () => {
        emitter.off('requestId' + requestId, eventListener);
      };
    })
  }

  // 监听
  addListener(eventType: string): void {
    emitter.on(eventType, () => {
      Logger.info('callback');
    })
  }

  // 移除监听
  removeListeners(count: number): void {
    emitter.off(count);
  }

  // 获取指定应用程序群组的目录路径
  getAppGroupDir(groupName: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let res = this.context.resourceManager.isRawDir(groupName);
      resolve(JSON.stringify(res));
    })
  }
}

