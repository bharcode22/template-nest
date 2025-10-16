import { Injectable } from '@nestjs/common';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class TestService {
  constructor(private prisma: PrismaService) {}
  async create(createTestDto: CreateTestDto) {

    const newUser = await this.prisma.user.create({
      data: {
        username : createTestDto.username,
        name     : createTestDto.name,
        email    : createTestDto.email,
        password : createTestDto.password,
        avatar   : createTestDto.avatar,
        provider : createTestDto.provider,
      },
    });

    return newUser
  }

  async findAll() {
    const userData = await this.prisma.user.findMany({
      where: {
        deleted_at: null
      }
    })

    return userData;
  }

  async findOne(id: string) {
    const userData = await this.prisma.user.findUnique({
      where: {
        id: id
      }
    })

    return userData;
  }

  update(id: number, updateTestDto: UpdateTestDto) {
    return `This action updates a #${id} test`;
  }

  remove(id: number) {
    return `This action removes a #${id} test`;
  }
}
