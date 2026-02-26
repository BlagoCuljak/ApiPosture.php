<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/admin')]
#[IsGranted('ROLE_ADMIN')]
class AdminController extends AbstractController
{
    #[Route('/dashboard', methods: ['GET'])]
    public function dashboard()
    {
        return $this->json(['status' => 'ok']);
    }

    #[Route('/settings', methods: ['POST'])]
    public function updateSettings()
    {
        // Update settings
    }

    #[Route('/export', methods: ['GET'])]
    #[IsGranted('ROLE_SUPER_ADMIN')]
    public function export()
    {
        // Export data
    }
}
