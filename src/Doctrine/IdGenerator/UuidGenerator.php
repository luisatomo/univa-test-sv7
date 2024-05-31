<?php

namespace App\Doctrine\IdGenerator;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Id\AbstractIdGenerator;
use Symfony\Component\Uid\UuidV4;

class UuidGenerator extends AbstractIdGenerator
{
    public function generateId(EntityManagerInterface $em, object|null $entity) : mixed
    {
        return UuidV4::v4()->toRfc4122();
    }
}
