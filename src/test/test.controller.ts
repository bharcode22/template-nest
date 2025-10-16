import { Controller, Get, Post, Body, Patch, Param, Delete, Req, Res, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';
import { TestService } from './test.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';

@Controller('test')
export class TestController {
  constructor(private readonly testService: TestService) {}

  @Post()
  async create(@Body() createTestDto: CreateTestDto, @Req() req: Request, @Res() res: Response):Promise<any> {
    try {
      const data = await this.testService.create(createTestDto);

      return res.status(HttpStatus.CREATED).json({
        message: "success to create data", 
        data: data
      })

    } catch (error: any) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: "error: ", 
        error: error.message
      })
    }
  }

  @Get()
  async findAll(@Req() req: Request, @Res() res: Response):Promise<any> {
    try {
      const data = await this.testService.findAll(); 

      return res.status(HttpStatus.OK).json({
        message: "succes to test data", 
        data: data
      })
    } catch (error: any) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: "error: ", 
        error: error.message
      })
    }
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    return await this.testService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateTestDto: UpdateTestDto) {
    return this.testService.update(+id, updateTestDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.testService.remove(+id);
  }
}
