import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): any {
    return 'Hallo from hk API';
  }
}
